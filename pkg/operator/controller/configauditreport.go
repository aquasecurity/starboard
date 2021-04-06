package controller

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	. "github.com/aquasecurity/starboard/pkg/operator/predicate"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ConfigAuditReportReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	kube.ObjectResolver
	LimitChecker
	kube.LogsReader
	configauditreport.Plugin
	starboard.PluginContext
	configauditreport.ReadWriter
}

func (r *ConfigAuditReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	workloads := []struct {
		kind       kube.Kind
		forObject  client.Object
		ownsObject client.Object
	}{
		{kind: kube.KindPod, forObject: &corev1.Pod{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindReplicaSet, forObject: &appsv1.ReplicaSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindReplicationController, forObject: &corev1.ReplicationController{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindStatefulSet, forObject: &appsv1.StatefulSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindDaemonSet, forObject: &appsv1.DaemonSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindCronJob, forObject: &batchv1beta1.CronJob{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindJob, forObject: &batchv1.Job{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
	}

	for _, workload := range workloads {
		err = ctrl.NewControllerManagedBy(mgr).
			For(workload.forObject, builder.WithPredicates(
				Not(ManagedByStarboardOperator),
				Not(IsBeingTerminated),
				installModePredicate,
			)).
			Owns(workload.ownsObject).
			Complete(r.reconcileWorkload(workload.kind))
		if err != nil {
			return err
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(
			InNamespace(r.Config.Namespace),
			ManagedByStarboardOperator,
			IsConfigAuditReportScan,
			JobHasAnyCondition,
		)).
		Complete(r.reconcileJobs())
}

func (r *ConfigAuditReportReconciler) reconcileWorkload(workloadKind kube.Kind) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("kind", workloadKind, "name", req.NamespacedName)

		workloadPartial := kube.GetPartialObjectFromKindAndNamespacedName(workloadKind, req.NamespacedName)

		log.V(1).Info("Getting workload from cache")
		workloadObj, err := r.GetObjectFromPartialObject(ctx, workloadPartial)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached workload that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting %s from cache: %w", workloadKind, err)
		}

		// Skip processing if it's a Pod controlled by a built-in K8s workload.
		if workloadKind == kube.KindPod {
			controller := metav1.GetControllerOf(workloadObj)
			if kube.IsBuiltInWorkload(controller) {
				log.V(1).Info("Ignoring managed pod", "controllerKind", controller.Kind, "controllerName", controller.Name)
				return ctrl.Result{}, nil
			}
		}

		// Skip processing if it's a Job controlled by CronJob.
		if workloadKind == kube.KindJob {
			controller := metav1.GetControllerOf(workloadObj)
			if controller != nil && controller.Kind == string(kube.KindCronJob) {
				log.V(1).Info("Ignoring managed job", "controllerKind", controller.Kind, "controllerName", controller.Name)
				return ctrl.Result{}, nil
			}
		}

		podSpec, err := kube.GetPodSpec(workloadObj)
		if err != nil {
			return ctrl.Result{}, err
		}
		podSpecHash := kube.ComputeHash(podSpec)
		pluginConfigHash, err := r.Plugin.GetConfigHash(r.PluginContext)
		if err != nil {
			return ctrl.Result{}, err
		}

		log = log.WithValues("podSpecHash", podSpecHash, "pluginConfigHash", pluginConfigHash)

		log.V(1).Info("Checking whether configuration audit report exists")
		hasReport, err := r.hasReport(ctx, workloadPartial, podSpecHash, pluginConfigHash)
		if err != nil {
			return ctrl.Result{}, err
		}

		if hasReport {
			log.V(1).Info("Configuration audit report exists")
			return ctrl.Result{}, nil
		}

		log.V(1).Info("Checking whether configuration audit has been scheduled")
		_, job, err := r.hasActiveScanJob(ctx, workloadPartial, podSpecHash)
		if err != nil {
			return ctrl.Result{}, err
		}
		if job != nil {
			log.V(1).Info("Configuration audit has been scheduled",
				"job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))
			return ctrl.Result{}, nil
		}

		limitExceeded, scanJobsCount, err := r.LimitChecker.Check(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("Checking scan jobs limit", "count", scanJobsCount, "limit", r.ConcurrentScanJobsLimit)

		if limitExceeded {
			log.V(1).Info("Pushing back scan job", "count", scanJobsCount, "retryAfter", r.ScanJobRetryAfter)
			return ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, nil
		}

		job, secrets, err := r.getScanJob(workloadPartial, workloadObj, podSpecHash)
		if err != nil {
			return ctrl.Result{}, err
		}

		for _, secret := range secrets {
			secret.Namespace = r.Config.Namespace
			err := r.Client.Create(ctx, secret)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("creating secret: %w", err)
			}
		}

		log.V(1).Info("Scheduling configuration audit", "secrets", len(secrets))
		err = r.Client.Create(ctx, job)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				// TODO Delete secrets that were created in the previous step. Alternatively we can delete them on schedule.
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("creating job: %w", err)
		}

		for _, secret := range secrets {
			err := controllerutil.SetOwnerReference(job, secret, r.Client.Scheme())
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("setting owner reference: %w", err)
			}
			err = r.Client.Update(ctx, secret)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("updating secret: %w", err)
			}
		}

		return ctrl.Result{}, nil
	}
}

func (r *ConfigAuditReportReconciler) hasReport(ctx context.Context, owner kube.Object, podSpecHash string, pluginConfigHash string) (bool, error) {
	report, err := r.ReadWriter.FindByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		return report.Labels[kube.LabelPodSpecHash] == podSpecHash &&
			report.Labels[kube.LabelPluginConfigHash] == pluginConfigHash, nil
	}
	return false, nil
}

func (r *ConfigAuditReportReconciler) hasActiveScanJob(ctx context.Context, owner kube.Object, hash string) (bool, *batchv1.Job, error) {
	jobName := r.getScanJobName(owner)
	job := &batchv1.Job{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.Config.Namespace, Name: jobName}, job)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("getting pod from cache: %w", err)
	}
	if job.Labels[kube.LabelPodSpecHash] == hash {
		return true, job, nil
	}
	return false, nil, nil
}

func (r *ConfigAuditReportReconciler) getScanJobName(workload kube.Object) string {
	return fmt.Sprintf("scan-configauditreport-%s", kube.ComputeHash(workload))
}

func (r *ConfigAuditReportReconciler) getScanJob(workload kube.Object, obj client.Object, podSpecHash string) (*batchv1.Job, []*corev1.Secret, error) {
	jobSpec, secrets, err := r.Plugin.GetScanJobSpec(r.PluginContext, obj)

	if err != nil {
		return nil, nil, err
	}

	configHash, err := r.Plugin.GetConfigHash(r.PluginContext)
	if err != nil {
		return nil, nil, err
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.getScanJobName(workload),
			Namespace: r.Config.Namespace,
			Labels: map[string]string{
				kube.LabelResourceKind:          string(workload.Kind),
				kube.LabelResourceName:          workload.Name,
				kube.LabelResourceNamespace:     workload.Namespace,
				kube.LabelK8SAppManagedBy:       kube.AppStarboardOperator,
				kube.LabelPodSpecHash:           podSpecHash,
				kube.LabelPluginConfigHash:      configHash,
				kube.LabelConfigAuditReportScan: "true",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(r.Config.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind:          string(workload.Kind),
						kube.LabelResourceName:          workload.Name,
						kube.LabelResourceNamespace:     workload.Namespace,
						kube.LabelK8SAppManagedBy:       kube.AppStarboardOperator,
						kube.LabelPodSpecHash:           podSpecHash,
						kube.LabelPluginConfigHash:      configHash,
						kube.LabelConfigAuditReportScan: "true",
					},
				},
				Spec: jobSpec,
			},
		},
	}, secrets, nil
}

func (r *ConfigAuditReportReconciler) reconcileJobs() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("job", req.NamespacedName)

		job := &batchv1.Job{}
		log.V(1).Info("Getting job from cache")
		err := r.Client.Get(ctx, req.NamespacedName, job)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached job that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
		}

		if len(job.Status.Conditions) == 0 {
			log.V(1).Info("Ignoring job without conditions")
			return ctrl.Result{}, nil
		}

		switch jobCondition := job.Status.Conditions[0].Type; jobCondition {
		case batchv1.JobComplete:
			err = r.processCompleteScanJob(ctx, job)
		case batchv1.JobFailed:
			err = r.processFailedScanJob(ctx, job)
		default:
			err = fmt.Errorf("unrecognized job condition: %v", jobCondition)
		}

		return ctrl.Result{}, err
	}

}

func (r *ConfigAuditReportReconciler) processCompleteScanJob(ctx context.Context, job *batchv1.Job) error {
	log := r.Logger.WithValues("job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))

	owner, err := kube.ObjectFromLabelsSet(job.Labels)
	if err != nil {
		return fmt.Errorf("getting workload from scan job labels set: %w", err)
	}

	log.V(1).Info("Processing complete scan job", "owner", owner)

	ownerObj, err := r.GetObjectFromPartialObject(ctx, owner)
	if err != nil {
		return err
	}

	podSpecHash, ok := job.Labels[kube.LabelPodSpecHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", kube.LabelPodSpecHash)
	}
	pluginConfigHash, ok := job.Labels[kube.LabelPluginConfigHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", kube.LabelPluginConfigHash)
	}

	hasConfigAuditReport, err := r.hasReport(ctx, owner, podSpecHash, pluginConfigHash)
	if err != nil {
		return err
	}

	if hasConfigAuditReport {
		log.V(1).Info("ConfigAuditReport already exist", "owner", owner)
		log.V(1).Info("Deleting complete scan job", "owner", owner)
		return r.Client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
	}

	logsStream, err := r.LogsReader.GetLogsByJobAndContainerName(ctx, job, r.Plugin.GetContainerName())
	if err != nil {
		return fmt.Errorf("getting logs: %w", err)
	}

	result, err := r.Plugin.ParseConfigAuditReportData(logsStream)
	defer func() {
		_ = logsStream.Close()
	}()

	report, err := configauditreport.NewBuilder(r.Client.Scheme()).
		Controller(ownerObj).
		PodSpecHash(podSpecHash).
		PluginConfigHash(pluginConfigHash).
		Result(result).
		Get()
	if err != nil {
		return err
	}

	err = r.ReadWriter.Write(ctx, report)
	if err != nil {
		return err
	}
	log.V(1).Info("Deleting complete scan job", "owner", owner)
	return r.Client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
}

func (r *ConfigAuditReportReconciler) processFailedScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	log := r.Logger.WithValues("job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))

	statuses, err := r.LogsReader.GetTerminatedContainersStatusesByJob(ctx, scanJob)
	if err != nil {
		return err
	}
	for container, status := range statuses {
		if status.ExitCode == 0 {
			continue
		}
		log.Error(nil, "Scan job container", "container", container, "status.reason", status.Reason, "status.message", status.Message)
	}
	log.V(1).Info("Deleting failed scan job")
	return r.Client.Delete(ctx, scanJob, client.PropagationPolicy(metav1.DeletePropagationBackground))
}
