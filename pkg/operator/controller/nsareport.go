package controller

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/nsa"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	. "github.com/aquasecurity/starboard/pkg/operator/predicate"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"strings"
)

// NsaReportReconciler  is encapsulation of cis-benchmark scanner and configaudit tools
// the nsa controller listen to nodes and variuose config objects and activate the relevant tools for security scanning
// all scanning jobs reconciliation produce NSA report (which follow the nsa specification)
type NsaReportReconciler struct {
	logr.Logger
	starboard.ConfigData
	etc.Config
	client.Client
	nsa.ReadWriter
	cisKubeBenchReportReconciler *CISKubeBenchReportReconciler
	configAuditReportReconciler  *ConfigAuditReportReconciler
}

func NewNsaReportReconciler(operatorConfig etc.Config,
	cisKubeBenchReportReconciler *CISKubeBenchReportReconciler, configAuditReportReconciler *ConfigAuditReportReconciler, logr logr.Logger,
	starboardConfig starboard.ConfigData, client client.Client, nsaReadWriter nsa.ReadWriter,
) *NsaReportReconciler {
	return &NsaReportReconciler{cisKubeBenchReportReconciler: cisKubeBenchReportReconciler,
		configAuditReportReconciler: configAuditReportReconciler,
		Config:                      operatorConfig,
		Client:                      client,
		ConfigData:                  starboardConfig,
		ReadWriter:                  nsaReadWriter,
		Logger:                      logr}
}

func NsaKubeBenchJobName(node *corev1.Node, f func(node *corev1.Node) string) string {
	commonName := KubeBenchJobName(node, f)
	return strings.Replace(commonName, "scan-cisbenchmark-", "scan-nsa-cisbenchmark-", -1)
}

func NsaConfigAuditJobName(obj client.Object) string {
	return strings.Replace(ConfigAuditJobName(obj), "scan-configauditreport-", "scan-nsa-configauditreport-", -1)
}

func (r *NsaReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := InstallModePredicate(r.Config)
	err = ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(IsLinuxNode)).
		Owns(&v1alpha1.ClusterNsaReport{}).
		Complete(r.reconcileNodes())
	if err != nil {
		return err
	}

	workloads := []struct {
		kind       kube.Kind
		forObject  client.Object
		ownsObject client.Object
	}{
		{kind: kube.KindPod, forObject: &corev1.Pod{}, ownsObject: &v1alpha1.ClusterNsaReport{}},
		{kind: kube.KindReplicaSet, forObject: &appsv1.ReplicaSet{}, ownsObject: &v1alpha1.ClusterNsaReport{}},
		{kind: kube.KindReplicationController, forObject: &corev1.ReplicationController{}, ownsObject: &v1alpha1.ClusterNsaReport{}},
		{kind: kube.KindStatefulSet, forObject: &appsv1.StatefulSet{}, ownsObject: &v1alpha1.ClusterNsaReport{}},
		{kind: kube.KindDaemonSet, forObject: &appsv1.DaemonSet{}, ownsObject: &v1alpha1.ClusterNsaReport{}},
		{kind: kube.KindCronJob, forObject: &batchv1beta1.CronJob{}, ownsObject: &v1alpha1.ClusterNsaReport{}},
		{kind: kube.KindJob, forObject: &batchv1.Job{}, ownsObject: &v1alpha1.ClusterNsaReport{}},
	}

	for _, workload := range workloads {
		err = ctrl.NewControllerManagedBy(mgr).
			For(workload.forObject, builder.WithPredicates(
				Not(ManagedByStarboardOperator),
				Not(IsBeingTerminated),
				installModePredicate,
			)).
			Owns(workload.ownsObject).
			Complete(r.reconcileResource(workload.kind))
		if err != nil {
			return err
		}
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(
			InNamespace(r.Config.Namespace),
			ManagedByStarboardOperator,
			IsNsaReportScan,
			JobHasAnyCondition,
		)).Complete(r.reconcileJobs())
}

func (r *NsaReportReconciler) reconcileNodes() reconcile.Func {
	return r.cisKubeBenchReportReconciler.reconcileJobs()
}

func (r *NsaReportReconciler) reconcileResource(kind kube.Kind) reconcile.Func {
	return r.configAuditReportReconciler.reconcileResource(kind)
}

func (r *NsaReportReconciler) reconcileJobs() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		job, err := getJobs(ctx, req, r)
		if err != nil {
			if errors.IsNotFound(err) {
				r.Logger.V(1).Info("Ignoring cached job that must have been deleted")
				return ctrl.Result{}, nil
			}
		}
		if strings.Contains(job.Name, "nsa-cisbenchmark") {
			return r.cisKubeBenchReportReconciler.reconcileKubeBenchJobs(ctx, req)
		}
		return r.configAuditReportReconciler.reconcileConfigAuditJob(ctx, req)
	}
}

func getJobs(ctx context.Context, req ctrl.Request, r *NsaReportReconciler) (*batchv1.Job, error) {
	log := r.Logger.WithValues("job", req.NamespacedName)
	job := &batchv1.Job{}
	log.V(1).Info("Getting job from cache")
	err := r.Client.Get(ctx, req.NamespacedName, job)
	if err != nil {
		return nil, fmt.Errorf("getting job from cache: %w", err)
	}
	return job, nil
}
