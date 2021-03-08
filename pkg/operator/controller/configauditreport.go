package controller

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	. "github.com/aquasecurity/starboard/pkg/operator/predicate"
	"github.com/aquasecurity/starboard/pkg/resources"
	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ConfigAuditReportReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	OwnerResolver
	LimitChecker
	kube.LogsReader
	configauditreport.Plugin
	configauditreport.ReadWriter
}

func (r *ConfigAuditReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := InstallModePredicate(r.Config)
	if err != nil {
		return err
	}
	err = ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}, builder.WithPredicates(
			Not(ManagedByStarboardOperator),
			Not(PodBeingTerminated),
			PodHasContainersReadyCondition,
			installModePredicate,
		)).
		Complete(r.reconcilePods())
	if err != nil {
		return err
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

func (r *ConfigAuditReportReconciler) reconcilePods() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("pod", req.NamespacedName)

		pod := &corev1.Pod{}

		err := r.Client.Get(ctx, req.NamespacedName, pod)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring pod that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting pod from cache: %w", err)
		}

		owner := resources.GetImmediateOwnerReference(pod)
		hash := resources.ComputeHash(pod.Spec)

		log.Info("Resolving workload properties",
			"owner", owner, "hash", hash)

		hasConfigAuditReport, err := r.hasConfigAuditReport(ctx, owner, hash)
		if err != nil {
			return ctrl.Result{}, err
		}

		if hasConfigAuditReport {
			return ctrl.Result{}, nil
		}

		ownerObj, err := r.OwnerResolver.Resolve(ctx, owner)
		if err != nil {
			return ctrl.Result{}, err
		}

		_, job, err := r.hasActiveScanJob(ctx, owner, hash)
		if err != nil {
			return ctrl.Result{}, nil
		}
		if job != nil {
			log.V(1).Info("Scan job already exists",
				"job", fmt.Sprintf("%s/%s", job.Namespace, job.Name),
				"owner", owner)
			return ctrl.Result{}, nil
		}

		limitExceeded, scanJobsCount, err := r.LimitChecker.Check(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		log.Info("Checking scan jobs limit", "count", scanJobsCount, "limit", r.ConcurrentScanJobsLimit)

		if limitExceeded {
			log.Info("Pushing back scan job", "count", scanJobsCount, "retryAfter", r.ScanJobRetryAfter)
			return ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, nil
		}

		gvk, err := apiutil.GVKForObject(ownerObj, r.Client.Scheme())
		if err != nil {
			return ctrl.Result{}, err
		}
		job, secrets, err := r.getScanJob(owner, ownerObj, gvk, hash)
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

		err = r.Client.Create(ctx, job)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("creating job: %w", err)
		}

		for _, secret := range secrets {
			err = controllerutil.SetOwnerReference(job, secret, r.Client.Scheme())
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("setting owner reference: %w", err)
			}
			err := r.Client.Update(ctx, secret)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("updating secret: %w", err)
			}
		}

		return ctrl.Result{}, nil
	}
}

func (r *ConfigAuditReportReconciler) hasConfigAuditReport(ctx context.Context, owner kube.Object, hash string) (bool, error) {
	report, err := r.ReadWriter.FindByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		if report.Labels[kube.LabelPodSpecHash] == hash {
			return true, nil
		}
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
	return fmt.Sprintf("scan-configauditreport-%s", resources.ComputeHash(workload))
}

func (r *ConfigAuditReportReconciler) getScanJob(workload kube.Object, obj client.Object, gvk schema.GroupVersionKind, hash string) (*batchv1.Job, []*corev1.Secret, error) {
	jobSpec, secrets, err := r.Plugin.GetScanJobSpec(workload, obj, gvk)

	if err != nil {
		return nil, nil, err
	}

	jobSpec.ServiceAccountName = r.Config.ServiceAccount

	jobName := r.getScanJobName(workload)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: r.Config.Namespace,
			Labels: map[string]string{
				kube.LabelResourceKind:          string(workload.Kind),
				kube.LabelResourceName:          workload.Name,
				kube.LabelResourceNamespace:     workload.Namespace,
				kube.LabelK8SAppManagedBy:       kube.AppStarboardOperator,
				kube.LabelPodSpecHash:           hash,
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
						kube.LabelPodSpecHash:           hash,
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
		err := r.Client.Get(ctx, req.NamespacedName, job)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring job that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
		}

		if len(job.Status.Conditions) == 0 {
			log.V(1).Info("Job has no conditions despite using predicate")
			return ctrl.Result{}, nil
		}

		switch jobCondition := job.Status.Conditions[0].Type; jobCondition {
		case batchv1.JobComplete:
			err = r.processCompleteScanJob(ctx, job)
		case batchv1.JobFailed:
			err = r.processFailedScanJob(ctx, job)
		default:
			err = fmt.Errorf("unrecognized scan job condition: %v", jobCondition)
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

	log.Info("Processing complete scan job", "owner", owner)

	ownerObj, err := r.OwnerResolver.Resolve(ctx, owner)
	if err != nil {
		return err
	}

	hash, ok := job.Labels[kube.LabelPodSpecHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", kube.LabelPodSpecHash)
	}

	hasConfigAuditReport, err := r.hasConfigAuditReport(ctx, owner, hash)
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

	result, err := r.Plugin.ParseConfigAuditResult(logsStream)
	defer func() {
		_ = logsStream.Close()
	}()

	report, err := configauditreport.NewBuilder(r.Client.Scheme()).
		Owner(ownerObj).
		PodSpecHash(hash).
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
