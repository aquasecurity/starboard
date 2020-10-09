package pod

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/operator/controller"

	"k8s.io/apimachinery/pkg/types"

	"github.com/aquasecurity/starboard/pkg/operator/resources"

	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/operator/reports"
	"github.com/aquasecurity/starboard/pkg/operator/scanner"
	batchv1 "k8s.io/api/batch/v1"

	"github.com/aquasecurity/starboard/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	log = ctrl.Log.WithName("controller").WithName("pod")
)

type PodController struct {
	Config  etc.Operator
	Client  client.Client
	Store   reports.StoreInterface
	Scanner scanner.VulnerabilityScanner
	Scheme  *runtime.Scheme
}

// Reconcile resolves the actual state of the system against the desired state of the system.
// The desired state is that there is a vulnerability report associated with the controller
// managing the given Pod.
// Since the scanning is asynchronous, the desired state is also when there's a pending scan
// Job for the underlying workload.
//
// As Kubernetes invokes the Reconcile() function multiple times throughout the lifecycle
// of a Pod, it is important that the implementation be idempotent to prevent the
// creation of duplicate scan Jobs or vulnerability reports.
//
// The Reconcile function returns two object which indicate whether or not Kubernetes
// should requeue the request.
func (r *PodController) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	pod := &corev1.Pod{}

	log := log.WithValues("pod", req.NamespacedName)

	installMode, err := r.Config.GetInstallMode()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting install mode: %w", err)
	}

	if r.IgnorePodInOperatorNamespace(installMode, req.NamespacedName) {
		log.V(1).Info("Ignoring Pod run in the operator namespace")
		return ctrl.Result{}, nil
	}

	// Retrieve the Pod from cache.
	err = r.Client.Get(ctx, req.NamespacedName, pod)
	if err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Ignoring Pod that must have been deleted")
		return ctrl.Result{}, nil
	} else if err != nil {
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
	log.V(1).Info("Resolving immediate Pod owner", "owner", owner)

	hash := controller.ComputeHash(pod.Spec)

	// Check if containers of the Pod have corresponding VulnerabilityReports.
	hasVulnerabilityReports, err := r.Store.HasVulnerabilityReports(ctx, owner, hash, resources.GetContainerImagesFromPodSpec(pod.Spec))
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting vulnerability reports: %w", err)
	}

	if hasVulnerabilityReports {
		log.V(1).Info("Ignoring Pod that already has VulnerabilityReports")
		return ctrl.Result{}, nil
	}

	// Create a scan Job to create VulnerabilityReports for the Pod containers images.
	err = r.ensureScanJob(ctx, owner, hash, pod)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensuring scan job: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *PodController) ensureScanJob(ctx context.Context, owner kube.Object, hash string, pod *corev1.Pod) error {
	log := log.WithValues("pod", fmt.Sprintf("%s/%s", pod.Namespace, pod.Name), "hash", hash)

	log.V(1).Info("Ensuring scan Job")

	jobList := &batchv1.JobList{}
	err := r.Client.List(ctx, jobList, client.MatchingLabels{
		kube.LabelResourceNamespace: pod.Namespace,
		kube.LabelResourceKind:      string(owner.Kind),
		kube.LabelResourceName:      owner.Name,
		etc.LabelPodSpecHash:        hash,
	}, client.InNamespace(r.Config.Namespace))
	if err != nil {
		return fmt.Errorf("listing jos: %w", err)
	}

	if len(jobList.Items) > 0 {
		log.V(1).Info("Scan job already exists",
			"job", fmt.Sprintf("%s/%s", jobList.Items[0].Namespace, jobList.Items[0].Name))
		return nil
	}

	jobMeta, err := r.GetJobMetaFrom(owner, hash, pod.Spec)
	if err != nil {
		return err
	}

	scanJob, err := r.Scanner.NewScanJob(jobMeta, scanner.Options{
		Namespace:          r.Config.Namespace,
		ServiceAccountName: r.Config.ServiceAccount,
		ScanJobTimeout:     r.Config.ScanJobTimeout,
	}, pod.Spec)
	if err != nil {
		return fmt.Errorf("constructing scan job: %w", err)
	}
	log.V(1).Info("Creating scan job",
		"job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))
	return r.Client.Create(ctx, scanJob)
}

func (r *PodController) GetJobMetaFrom(owner kube.Object, hash string, spec corev1.PodSpec) (scanner.JobMeta, error) {
	containerImages := resources.GetContainerImagesFromPodSpec(spec)
	containerImagesAsJSON, err := containerImages.AsJSON()
	if err != nil {
		return scanner.JobMeta{}, err
	}

	return scanner.JobMeta{
		Labels: map[string]string{
			kube.LabelResourceKind:         string(owner.Kind),
			kube.LabelResourceName:         owner.Name,
			kube.LabelResourceNamespace:    owner.Namespace,
			"app.kubernetes.io/managed-by": "starboard-operator",
			etc.LabelPodSpecHash:           hash,
		},
		Annotations: map[string]string{
			kube.AnnotationContainerImages: containerImagesAsJSON,
		},
	}, nil
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
		pod.Namespace == r.Config.Namespace {
		return true
	}

	if installMode == etc.InstallModeMultiNamespace &&
		pod.Namespace == r.Config.Namespace &&
		!SliceContainsString(r.Config.GetTargetNamespaces(), r.Config.Namespace) {
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
