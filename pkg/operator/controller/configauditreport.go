package controller

import (
	. "github.com/aquasecurity/starboard/pkg/operator/predicate"

	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ConfigAuditReportReconciler struct {
	logr.Logger
	etc.Config
	starboard.ConfigData
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
		_, job, err := r.hasActiveScanJob(ctx, workloadObj, podSpecHash)
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

		scanJobTolerations, err := r.ConfigData.GetScanJobTolerations()
		if err != nil {
			return ctrl.Result{}, err
		}

		scanJobAnnotations, err := r.ConfigData.GetScanJobAnnotations()
		if err != nil {
			return ctrl.Result{}, err
		}

		job, secrets, err := configauditreport.NewScanJob().
			WithPlugin(r.Plugin).
			WithPluginContext(r.PluginContext).
			WithTimeout(r.Config.ScanJobTimeout).
			WithObject(workloadObj).
			WithTolerations(scanJobTolerations).
			WithScanJobAnnotations(scanJobAnnotations).
			Get()
		if err != nil {
			return ctrl.Result{}, err
		}

		for _, secret := range secrets {
			err := r.Client.Create(ctx, secret)
			if err != nil {
				if !errors.IsAlreadyExists(err) {
					log.V(1).Info("Secret already exists", "secretName", secret.Name)
					return ctrl.Result{}, nil
				}
				return ctrl.Result{}, fmt.Errorf("creating secret: %w", err)
			}
		}

		log.V(1).Info("Scheduling configuration audit", "secrets", len(secrets))
		err = r.Client.Create(ctx, job)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				// TODO Delete secrets that were created in the previous step. Alternatively we can delete them on schedule.
				log.V(1).Info("Job already exists", "jobName", job.Name)
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
	// TODO FindByOwner should accept optional label selector to further narrow down search results
	report, err := r.ReadWriter.FindByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		return report.Labels[starboard.LabelPodSpecHash] == podSpecHash &&
			report.Labels[starboard.LabelPluginConfigHash] == pluginConfigHash, nil
	}
	return false, nil
}

func (r *ConfigAuditReportReconciler) hasActiveScanJob(ctx context.Context, obj client.Object, hash string) (bool, *batchv1.Job, error) {
	jobName := configauditreport.GetScanJobName(obj)
	job := &batchv1.Job{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.Config.Namespace, Name: jobName}, job)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("getting pod from cache: %w", err)
	}
	if job.Labels[starboard.LabelPodSpecHash] == hash {
		return true, job, nil
	}
	return false, nil, nil
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
		if errors.IsNotFound(err) {
			log.V(1).Info("Deleting complete scan job for workload that must have been deleted")
			return r.deleteJob(ctx, job)
		}
		return fmt.Errorf("getting object from partial object: %w", err)
	}

	podSpecHash, ok := job.Labels[starboard.LabelPodSpecHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", starboard.LabelPodSpecHash)
	}
	pluginConfigHash, ok := job.Labels[starboard.LabelPluginConfigHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", starboard.LabelPluginConfigHash)
	}

	hasReport, err := r.hasReport(ctx, owner, podSpecHash, pluginConfigHash)
	if err != nil {
		return err
	}

	if hasReport {
		log.V(1).Info("ConfigAuditReport already exist", "owner", owner)
		log.V(1).Info("Deleting complete scan job", "owner", owner)
		return r.deleteJob(ctx, job)
	}

	logsStream, err := r.LogsReader.GetLogsByJobAndContainerName(ctx, job, r.Plugin.GetContainerName())
	if err != nil {
		return fmt.Errorf("getting logs: %w", err)
	}

	result, err := r.Plugin.ParseConfigAuditReportData(r.PluginContext, logsStream)
	defer func() {
		_ = logsStream.Close()
	}()

	report, err := configauditreport.NewReportBuilder(r.Client.Scheme()).
		Controller(ownerObj).
		PodSpecHash(podSpecHash).
		PluginConfigHash(pluginConfigHash).
		Data(result).
		Get()
	if err != nil {
		return err
	}

	err = r.ReadWriter.Write(ctx, report)
	if err != nil {
		return err
	}
	log.V(1).Info("Deleting complete scan job", "owner", owner)
	return r.deleteJob(ctx, job)
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

func (r *ConfigAuditReportReconciler) deleteJob(ctx context.Context, job *batchv1.Job) error {
	err := r.Client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("deleting job: %w", err)
	}
	return nil
}
