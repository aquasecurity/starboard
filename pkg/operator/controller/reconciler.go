package controller

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/docker"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/operator/logs"
	"github.com/aquasecurity/starboard/pkg/resources"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type Reconciler interface {
	SubmitScanJob(ctx context.Context, podSpec corev1.PodSpec, owner kube.Object, images kube.ContainerImages, hash string) error
	ParseLogsAndSaveVulnerabilityReports(ctx context.Context, scanJob *batchv1.Job, workload kube.Object, containerImages kube.ContainerImages, hash string) error
	GetPodControlledBy(ctx context.Context, job *batchv1.Job) (*corev1.Pod, error)
}

func NewReconciler(scheme *runtime.Scheme,
	config etc.Config,
	client client.Client,
	store vulnerabilityreport.ReadWriter,
	idGenerator ext.IDGenerator,
	scanner vulnerabilityreport.Plugin,
	logsReader *logs.Reader,
) Reconciler {
	return &reconciler{
		scheme:        scheme,
		config:        config,
		client:        client,
		store:         store,
		idGenerator:   idGenerator,
		scanner:       scanner,
		logsReader:    logsReader,
		SecretsReader: kube.NewControllerRuntimeSecretsReader(client),
	}
}

type reconciler struct {
	scheme      *runtime.Scheme
	config      etc.Config
	client      client.Client
	store       vulnerabilityreport.ReadWriter
	idGenerator ext.IDGenerator
	scanner     vulnerabilityreport.Plugin
	logsReader  *logs.Reader
	kube.SecretsReader
}

func (r *reconciler) SubmitScanJob(ctx context.Context, spec corev1.PodSpec, owner kube.Object, images kube.ContainerImages, hash string) error {
	credentials, err := r.getCredentials(ctx, spec, owner.Namespace)
	if err != nil {
		return err
	}

	templateSpec, secrets, err := r.scanner.GetScanJobSpec(spec, credentials)
	if err != nil {
		return err
	}

	containerImagesAsJSON, err := images.AsJSON()
	if err != nil {
		return err
	}

	templateSpec.ServiceAccountName = r.config.ServiceAccount

	for _, secret := range secrets {
		secret.Namespace = r.config.Namespace
		err := r.client.Create(ctx, secret)
		if err != nil {
			return fmt.Errorf("creating secret: %w", err)
		}
	}

	scanJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.idGenerator.GenerateID(),
			Namespace: r.config.Namespace,
			Labels: map[string]string{
				kube.LabelResourceKind:      string(owner.Kind),
				kube.LabelResourceName:      owner.Name,
				kube.LabelResourceNamespace: owner.Namespace,
				kube.LabelPodSpecHash:       hash,
				kube.LabelK8SAppManagedBy:   kube.AppStarboardOperator,
			},
			Annotations: map[string]string{
				kube.AnnotationContainerImages: containerImagesAsJSON,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(r.config.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind:      string(owner.Kind),
						kube.LabelResourceName:      owner.Name,
						kube.LabelResourceNamespace: owner.Namespace,
						kube.LabelPodSpecHash:       hash,
						kube.LabelK8SAppManagedBy:   kube.AppStarboardOperator,
					},
				},
				Spec: templateSpec,
			},
		},
	}

	err = r.client.Create(ctx, scanJob)
	if err != nil {
		return fmt.Errorf("creating job: %w", err)
	}

	for _, secret := range secrets {
		err = controllerutil.SetOwnerReference(scanJob, secret, r.scheme)
		if err != nil {
			return fmt.Errorf("setting owner reference: %w", err)
		}
		err := r.client.Update(ctx, secret)
		if err != nil {
			return fmt.Errorf("updating secret: %w", err)
		}
	}

	return nil
}

func (r *reconciler) getCredentials(ctx context.Context, spec corev1.PodSpec, ns string) (map[string]docker.Auth, error) {
	imagePullSecrets, err := r.ListImagePullSecretsByPodSpec(ctx, spec, ns)
	if err != nil {
		return nil, err
	}
	return kube.MapContainerNamesToDockerAuths(resources.GetContainerImagesFromPodSpec(spec), imagePullSecrets)
}

func (r *reconciler) ParseLogsAndSaveVulnerabilityReports(ctx context.Context, scanJob *batchv1.Job, workload kube.Object, containerImages kube.ContainerImages, hash string) error {
	owner, err := r.getRuntimeObjectFor(ctx, workload)
	if err != nil {
		return err
	}

	pod, err := r.GetPodControlledBy(ctx, scanJob)
	if err != nil {
		return fmt.Errorf("getting pod controlled by %s/%s: %w", scanJob.Namespace, scanJob.Name, err)
	}

	var vulnerabilityReports []v1alpha1.VulnerabilityReport

	for _, container := range pod.Spec.Containers {
		logsReader, err := r.logsReader.GetLogsForPod(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, &corev1.PodLogOptions{
			Container: container.Name,
			Follow:    true,
		})
		if err != nil {
			return fmt.Errorf("getting logs for pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		scanResult, err := r.scanner.ParseVulnerabilityScanResult(containerImages[container.Name], logsReader)
		if err != nil {
			return err
		}
		_ = logsReader.Close()

		report, err := vulnerabilityreport.NewBuilder(r.scheme).
			Owner(owner).
			Container(container.Name).
			Result(scanResult).
			PodSpecHash(hash).Get()
		if err != nil {
			return err
		}

		vulnerabilityReports = append(vulnerabilityReports, report)
	}

	return r.store.Write(ctx, vulnerabilityReports)
}

// TODO Add to utilities used both by CLI and Operator
func (r *reconciler) getRuntimeObjectFor(ctx context.Context, workload kube.Object) (metav1.Object, error) {
	var obj client.Object
	switch workload.Kind {
	case kube.KindPod:
		obj = &corev1.Pod{}
	case kube.KindReplicaSet:
		obj = &appsv1.ReplicaSet{}
	case kube.KindReplicationController:
		obj = &corev1.ReplicationController{}
	case kube.KindDeployment:
		obj = &appsv1.Deployment{}
	case kube.KindStatefulSet:
		obj = &appsv1.StatefulSet{}
	case kube.KindDaemonSet:
		obj = &appsv1.DaemonSet{}
	case kube.KindCronJob:
		obj = &batchv1beta1.CronJob{}
	case kube.KindJob:
		obj = &batchv1.Job{}
	default:
		return nil, fmt.Errorf("unknown workload kind: %s", workload.Kind)
	}
	err := r.client.Get(ctx, types.NamespacedName{Name: workload.Name, Namespace: workload.Namespace}, obj)
	if err != nil {
		return nil, err
	}
	return obj.(metav1.Object), nil
}

// TODO Add to utilities used both by CLI and Operator
func (r *reconciler) GetPodControlledBy(ctx context.Context, job *batchv1.Job) (*corev1.Pod, error) {
	controllerUID, ok := job.Spec.Selector.MatchLabels["controller-uid"]
	if !ok {
		return nil, fmt.Errorf("controller-uid not found for job %s/%s", job.Namespace, job.Name)
	}
	podList := &corev1.PodList{}
	err := r.client.List(ctx, podList, client.MatchingLabels{"controller-uid": controllerUID})
	if err != nil {
		return nil, fmt.Errorf("listing pods controlled by job %s/%s: %w", job.Namespace, job.Name, err)
	}
	if len(podList.Items) != 1 {
		return nil, fmt.Errorf("expected 1 Pod, but got %d", len(podList.Items))
	}
	return podList.Items[0].DeepCopy(), nil
}
