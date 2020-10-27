package job

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/operator/controller"

	"github.com/aquasecurity/starboard/pkg/resources"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/starboard/pkg/kube"
	pods "github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"k8s.io/apimachinery/pkg/api/errors"

	batchv1 "k8s.io/api/batch/v1"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	log = ctrl.Log.WithName("controller").WithName("job")
)

type JobController struct {
	etc.Operator
	client.Client
	controller.Analyzer
	controller.Reconciler
}

func (r *JobController) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := log.WithValues("job", req.NamespacedName)

	if req.Namespace != r.Namespace {
		log.V(1).Info("Ignoring Job not managed by this operator")
		return ctrl.Result{}, nil
	}

	job := &batchv1.Job{}
	err := r.Client.Get(ctx, req.NamespacedName, job)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Ignoring Job that must have been deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
	}

	if len(job.Status.Conditions) == 0 {
		log.V(1).Info("Ignoring Job without status conditions")
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

func (r *JobController) processCompleteScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	log := log.WithValues("job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))
	owner, err := kube.ObjectFromLabelsSet(scanJob.Labels)
	if err != nil {
		return fmt.Errorf("getting workload from scan job labels set: %w", err)
	}

	containerImages, err := resources.GetContainerImagesFromJob(scanJob)
	if err != nil {
		return fmt.Errorf("getting container images: %w", err)
	}

	hash, ok := scanJob.Labels[kube.LabelPodSpecHash]
	if !ok {
		return fmt.Errorf("expected label %s not set", kube.LabelPodSpecHash)
	}

	log.V(1).Info("Resolving workload properties",
		"owner", owner, "hash", hash, "containerImages", containerImages)

	hasVulnerabilityReports, err := r.HasVulnerabilityReports(ctx, owner, containerImages, hash)
	if err != nil {
		return err
	}

	if hasVulnerabilityReports {
		log.V(1).Info("VulnerabilityReports already exist", "owner", owner)
		log.V(1).Info("Deleting scan job")
		return r.Client.Delete(ctx, scanJob, client.PropagationPolicy(metav1.DeletePropagationBackground))
	}

	err = r.ParseLogsAndSaveVulnerabilityReports(ctx, scanJob, owner, containerImages, hash)
	if err != nil {
		return err
	}
	log.V(1).Info("Deleting complete scan job")
	return r.Client.Delete(ctx, scanJob, client.PropagationPolicy(metav1.DeletePropagationBackground))
}

func (r *JobController) processFailedScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	log := log.WithValues("job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))

	pod, err := r.Reconciler.GetPodControlledBy(ctx, scanJob)
	if err != nil {
		return err
	}
	statuses := pods.GetTerminatedContainersStatusesByPod(pod)
	for container, status := range statuses {
		if status.ExitCode == 0 {
			continue
		}
		log.Error(nil, "Scan job container", "container", container, "status.reason", status.Reason, "status.message", status.Message)
	}
	log.V(1).Info("Deleting failed scan job")
	return r.Client.Delete(ctx, scanJob, client.PropagationPolicy(metav1.DeletePropagationBackground))
}

func (r *JobController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}).
		Complete(r)
}
