package pod

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/operator/controller"

	"k8s.io/apimachinery/pkg/types"

	"github.com/aquasecurity/starboard/pkg/resources"

	"github.com/aquasecurity/starboard/pkg/operator/etc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	log = ctrl.Log.WithName("controller").WithName("pod")
)

type PodController struct {
	etc.Operator
	client.Client
	controller.Analyzer
	controller.Reconciler
}

func (r *PodController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	pod := &corev1.Pod{}

	log := log.WithValues("pod", req.NamespacedName)

	installMode, err := r.GetInstallMode()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting install mode: %w", err)
	}

	if r.IgnorePodInOperatorNamespace(installMode, req.NamespacedName) {
		log.V(1).Info("Ignoring Pod run in the operator namespace")
		return ctrl.Result{}, nil
	}

	// Retrieve the Pod from cache.
	err = r.Get(ctx, req.NamespacedName, pod)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Ignoring Pod that must have been deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("getting pod from cache: %w", err)
	}

	// Check if the Pod is managed by the operator, i.e. is controlled by a scan Job created by the PodController.
	if IsPodManagedByStarboardOperator(pod) {
		log.V(1).Info("Ignoring Pod managed by this operator")
		return ctrl.Result{}, nil
	}

	// Check if the Pod is being terminated.
	if pod.DeletionTimestamp != nil {
		log.V(1).Info("Ignoring Pod that is being terminated")
		return ctrl.Result{}, nil
	}

	// Check if the Pod containers are ready.
	if !resources.HasContainersReadyCondition(pod) {
		log.V(1).Info("Ignoring Pod that is being scheduled")
		return ctrl.Result{}, nil
	}

	owner := resources.GetImmediateOwnerReference(pod)
	containerImages := resources.GetContainerImagesFromPodSpec(pod.Spec)
	hash := resources.ComputeHash(pod.Spec)

	log.V(1).Info("Resolving workload properties",
		"owner", owner, "hash", hash, "containerImages", containerImages)

	// Check if containers of the Pod have corresponding VulnerabilityReports.
	hasVulnerabilityReports, err := r.HasVulnerabilityReports(ctx, owner, containerImages, hash)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting vulnerability reports: %w", err)
	}

	if hasVulnerabilityReports {
		log.V(1).Info("Ignoring Pod that already has VulnerabilityReports")
		return ctrl.Result{}, nil
	}

	scanJob, err := r.GetActiveScanJob(ctx, owner, hash)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("checking scan job: %w", err)
	}

	if scanJob != nil {
		log.V(1).Info("Scan job already exists",
			"job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))
		return ctrl.Result{}, nil
	}

	limitExceeded, scanJobsCount, err := r.IsConcurrentScanJobsLimitExceeded(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	log.Info("Checking scan jobs limit", "count", scanJobsCount, "limit", r.ConcurrentScanJobsLimit)

	if limitExceeded {
		log.Info("Pushing back scan job", "count", scanJobsCount, "retryAfter", r.ScanJobRetryAfter)
		return ctrl.Result{RequeueAfter: r.ScanJobRetryAfter}, nil
	}

	return ctrl.Result{}, r.SubmitScanJob(ctx, pod.Spec, owner, containerImages, hash)
}

// IgnorePodInOperatorNamespace determines whether to reconcile the specified Pod
// based on the give InstallMode or not. Returns true if the Pod should be ignored,
// false otherwise.
//
// In the SingleNamespace install mode we're configuring Client cache
// to watch the operator namespace, in which the operator runs scan Jobs.
// However, we do not want to scan the workloads that might run in the
// operator namespace.
//
// In the MultiNamespace install mode we're configuring Client cache
// to watch the operator namespace, in which the operator runs scan Jobs.
// However, we do not want to scan the workloads that might run in the
// operator namespace unless the operator namespace is added to the list
// of target namespaces.
func (r *PodController) IgnorePodInOperatorNamespace(installMode etc.InstallMode, pod types.NamespacedName) bool {
	if installMode == etc.InstallModeSingleNamespace &&
		pod.Namespace == r.Namespace {
		return true
	}

	if installMode == etc.InstallModeMultiNamespace &&
		pod.Namespace == r.Namespace &&
		!SliceContainsString(r.GetTargetNamespaces(), r.Namespace) {
		return true
	}

	return false
}

// IsPodManagedByStarboardOperator returns true if the specified Pod
// is managed by the Starboard Operator, false otherwise.
//
// We define managed Pods as ones controlled by Jobs created by the Starboard Operator.
// They're labeled with `app.kubernetes.io/managed-by=starboard-operator`.
func IsPodManagedByStarboardOperator(pod *corev1.Pod) bool {
	managedBy, exists := pod.Labels["app.kubernetes.io/managed-by"]
	return exists && managedBy == "starboard-operator"
}

func (r *PodController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

// SliceContainsString returns true if the specified slice of strings
// contains the give value, false otherwise.
func SliceContainsString(slice []string, value string) bool {
	exists := false
	for _, targetNamespace := range slice {
		if targetNamespace == value {
			exists = true
		}
	}
	return exists
}
