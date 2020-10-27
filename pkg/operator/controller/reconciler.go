package controller

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/operator/logs"
	"github.com/aquasecurity/starboard/pkg/operator/scanner"
	"github.com/aquasecurity/starboard/pkg/scanners"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Reconciler interface {
	SubmitScanJob(ctx context.Context, podSpec corev1.PodSpec, owner kube.Object, images kube.ContainerImages, hash string) error
	ParseLogsAndSaveVulnerabilityReports(ctx context.Context, scanJob *batchv1.Job, workload kube.Object, containerImages kube.ContainerImages, hash string) error
	GetPodControlledBy(ctx context.Context, job *batchv1.Job) (*corev1.Pod, error)
}

func NewReconciler(scheme *runtime.Scheme,
	config etc.Operator,
	client client.Client,
	store vulnerabilityreport.StoreInterface,
	idGenerator ext.IDGenerator,
	scanner scanner.VulnerabilityScanner,
	logsReader *logs.Reader) Reconciler {
	return &reconciler{
		scheme:      scheme,
		config:      config,
		client:      client,
		store:       store,
		idGenerator: idGenerator,
		scanner:     scanner,
		logsReader:  logsReader,
	}
}

type reconciler struct {
	scheme      *runtime.Scheme
	config      etc.Operator
	client      client.Client
	store       vulnerabilityreport.StoreInterface
	idGenerator ext.IDGenerator
	scanner     scanner.VulnerabilityScanner
	logsReader  *logs.Reader
}

// this should be a template method
func (r *reconciler) SubmitScanJob(ctx context.Context, podSpec corev1.PodSpec, owner kube.Object, containerImages kube.ContainerImages, hash string) error {
	jobMeta, err := r.getJobMetaFrom(owner, hash, containerImages)
	if err != nil {
		return err
	}

	scanJob, err := r.newScanJob(podSpec, scanner.Options{
		Namespace:          r.config.Namespace,
		ServiceAccountName: r.config.ServiceAccount,
		ScanJobTimeout:     r.config.ScanJobTimeout,
	}, jobMeta)
	if err != nil {
		return fmt.Errorf("constructing scan job: %w", err)
	}
	//log.V(1).Info("Creating scan job",
	//	"job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))
	return r.client.Create(ctx, scanJob)
}

func (r *reconciler) getJobMetaFrom(owner kube.Object, hash string, containerImages kube.ContainerImages) (scanner.JobMeta, error) {
	containerImagesAsJSON, err := containerImages.AsJSON()
	if err != nil {
		return scanner.JobMeta{}, err
	}

	return scanner.JobMeta{
		Name: r.idGenerator.GenerateID(),
		Labels: map[string]string{
			kube.LabelResourceKind:         string(owner.Kind),
			kube.LabelResourceName:         owner.Name,
			kube.LabelResourceNamespace:    owner.Namespace,
			"app.kubernetes.io/managed-by": "starboard-operator",
			kube.LabelPodSpecHash:          hash,
		},
		Annotations: map[string]string{
			kube.AnnotationContainerImages: containerImagesAsJSON,
		},
	}, nil
}

func (r *reconciler) newScanJob(spec corev1.PodSpec, options scanner.Options, meta scanner.JobMeta) (*batchv1.Job, error) {
	template, err := r.scanner.GetPodTemplateSpec(spec, options)
	if err != nil {
		return nil, err
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        meta.Name,
			Namespace:   options.Namespace,
			Labels:      meta.Labels,
			Annotations: meta.Annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(options.ScanJobTimeout),
			Template:              template,
		},
	}, nil
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

		reportName, err := vulnerabilityreport.NewNameBuilder(r.scheme).
			Owner(owner).
			Container(container.Name).Get()
		if err != nil {
			return err
		}

		report, err := vulnerabilityreport.NewBuilder(r.scheme).
			Owner(owner).
			Container(container.Name).
			ReportName(reportName).
			ScanResult(scanResult).
			PodSpecHash(hash).Get()
		if err != nil {
			return err
		}

		vulnerabilityReports = append(vulnerabilityReports, report)
	}

	return r.store.Save(ctx, vulnerabilityReports)
}

// TODO Add to utilities used both by CLI and Operator
func (r *reconciler) getRuntimeObjectFor(ctx context.Context, workload kube.Object) (metav1.Object, error) {
	var obj runtime.Object
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
		obj = &v1beta1.CronJob{}
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
