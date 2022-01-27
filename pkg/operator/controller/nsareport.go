package controller

import (
	"fmt"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/nsa"
	. "github.com/aquasecurity/starboard/pkg/operator/predicate"
	"strings"

	"context"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// NsaReportReconciler  is encapsulation of cis-benchmark scanner and configaudit tools
// the nsa controller listen to nodes and variuose config objects and activate the relevant tools for security scanning
// all scanning jobs reconciliation produce NSA report (which follow the nsa specification)
type NsaReportReconciler struct {
	logr.Logger
	nsa.ReadWriter
	starboard.ConfigData
	etc.Config
	client.Client
	cisKubeBenchReportReconciler *CISKubeBenchReportReconciler
	configAuditReportReconciler  *ConfigAuditReportReconciler
}

func NewNsaReportReconciler(operatorConfig etc.Config,
	objectResolver kube.ObjectResolver,
	confPlugin configauditreport.Plugin,
	logr logr.Logger,
	starboardConfig starboard.ConfigData,
	client client.Client,
	logsReader kube.LogsReader,
	limitChecker LimitChecker,
	rw nsa.ReadWriter,
	plugin kubebench.Plugin) *NsaReportReconciler {

	// construct cisBenchmark reconciler
	cisKubeBenchReportReconciler := &CISKubeBenchReportReconciler{
		Logger:       logr,
		Config:       operatorConfig,
		ConfigData:   starboardConfig,
		Client:       client,
		LogsReader:   logsReader,
		LimitChecker: limitChecker,
		Plugin:       plugin,
	}
	// construct audit-config reconciler
	configAuditReportReconciler := &ConfigAuditReportReconciler{
		Logger:         logr,
		Config:         operatorConfig,
		ConfigData:     starboardConfig,
		Client:         client,
		LogsReader:     logsReader,
		LimitChecker:   limitChecker,
		Plugin:         confPlugin,
		ObjectResolver: objectResolver,
	}
	return &NsaReportReconciler{cisKubeBenchReportReconciler: cisKubeBenchReportReconciler,
		configAuditReportReconciler: configAuditReportReconciler,
		ReadWriter:                  rw,
		Config:                      operatorConfig,
		Client:                      client,
		ConfigData:                  starboardConfig,
		Logger:                      logr}
}

func (r *NsaReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(IsLinuxNode)).
		Owns(&v1alpha1.CISKubeBenchReport{}).
		Complete(r.reconcileNodes(r))
	if err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(
			InNamespace(r.Config.Namespace),
			ManagedByStarboardOperator,
			IsKubeBenchReportScan,
			JobHasAnyCondition,
		)).
		Complete(r.reconcileJobs(r))
}

type Conductor interface {
	ApplyReport(ctx context.Context, log logr.Logger, report interface{}) error
	FindByOwner(ctx context.Context, node kube.ObjectRef) (interface{}, error)
	AddJobMiddleName() string
}

func (r *NsaReportReconciler) FindByOwner(ctx context.Context, node kube.ObjectRef) (interface{}, error) {
	return r.ReadWriter.FindByOwner(ctx, node)
}

func (r *NsaReportReconciler) AddJobMiddleName() string {
	//add nsa middle name cis-benchmark classic scan
	return "nsa-"
}

func (r *NsaReportReconciler) reconcileNodes(conduct Conductor) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		return r.cisKubeBenchReportReconciler.reconcileNodeEvent(ctx, req, conduct)
	}
}

func (r *NsaReportReconciler) reconcileJobs(conduct Conductor) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("job", req.NamespacedName)
		job, err := findJob(ctx, req, r.Client)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached job that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
		}
		if strings.Contains(job.Name, "cisbenchmark") {
			return r.cisKubeBenchReportReconciler.reconcileKubeBench(ctx, req, conduct)
		}
		return r.configAuditReportReconciler.reconcileConfigAudit(ctx, req, conduct)
	}
}

func (r *NsaReportReconciler) ApplyReport(ctx context.Context, log logr.Logger, report interface{}) error {
	if cbr, ok := report.(v1alpha1.CISKubeBenchReport); ok {
		log.V(1).Info("Writing NSA report", "reportName", cbr.Name)
		err := r.ReadWriter.WriteInfra(ctx, cbr)
		return err
	}
	if cbr, ok := report.(v1alpha1.ClusterConfigAuditReport); ok {
		err := r.ReadWriter.WriteConfig(ctx, cbr)
		return err
	}
	return fmt.Errorf("wrong Nsa report type")
}
