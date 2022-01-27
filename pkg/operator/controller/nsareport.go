package controller

import (
	"fmt"
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

// NsaReportReconciler reconciles corev1.Node and corev1.Job objects
// to check cluster nodes configuration with CIS Kubernetes Benchmark and saves
// results as v1alpha1.CISKubeBenchReport objects.
// Each v1alpha1.CISKubeBenchReport is controlled by the corev1.Node for which
// it was generated. Additionally, the NsaReportReconciler.SetupWithManager
// method informs the ctrl.Manager that this controller reconciles nodes that
// own benchmark reports, so that it will automatically call the reconcile
// callback on the underlying corev1.Node when a v1alpha1.NsaReportReconciler
// changes, is deleted, etc.
type NsaReportReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	kube.LogsReader
	LimitChecker
	nsa.ReadWriter
	kubebench.Plugin
	starboard.ConfigData
	*CISKubeBenchReportReconciler
	*ConfigAuditReportReconciler
}

func NewNsaReportReconciler(operatorConfig etc.Config, logr logr.Logger, starboardConfig starboard.ConfigData, client client.Client, logsReader kube.LogsReader, limitChecker LimitChecker, rw nsa.ReadWriter, plugin kubebench.Plugin) *NsaReportReconciler {
	cisKubeBenchReportReconciler := &CISKubeBenchReportReconciler{
		Logger:       logr,
		Config:       operatorConfig,
		ConfigData:   starboardConfig,
		Client:       client,
		LogsReader:   logsReader,
		LimitChecker: limitChecker,
		Plugin:       plugin,
	}
	return &NsaReportReconciler{CISKubeBenchReportReconciler: cisKubeBenchReportReconciler, ReadWriter: rw}
}

func (r *NsaReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(IsLinuxNode)).
		Owns(&v1alpha1.ClusterNsaReport{}).
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

func (r *NsaReportReconciler) AddJobMiddleName() string {
	//add nsa middle name cis-benchmark classic scan
	return "nsa-"
}

func (r *NsaReportReconciler) reconcileNodes(conduct Conductor) reconcile.Func {
	return r.CISKubeBenchReportReconciler.reconcileNodes(conduct)
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
			return r.reconcileKubeBench(ctx, req, conduct)
		}
		return r.reconcileConfigAudit(ctx, req, conduct)
	}
}

func (r *NsaReportReconciler) ApplyReport(ctx context.Context, log logr.Logger, report interface{}) error {
	if cbr, ok := report.(v1alpha1.CISKubeBenchReport); ok {
		log.V(1).Info("Writing CIS Kubernetes Benchmark report", "reportName", cbr.Name)
		err := r.ReadWriter.WriteInfra(ctx, cbr)
		return err
	}
	if cbr, ok := report.(v1alpha1.ClusterConfigAuditReport); ok {
		err := r.ReadWriter.WriteConfig(ctx, cbr)
		return err
	}
	return fmt.Errorf("wrong Nsa report type")
}
