package polaris

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/scanners"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"k8s.io/utils/pointer"
)

const (
	polarisContainerName = "polaris"
	configVolume         = "config"
)

type Config interface {
	GetPolarisImageRef() (string, error)
}

type Scanner struct {
	scheme    *runtime.Scheme
	clientset kubernetes.Interface
	config    Config
	opts      kube.ScannerOpts
	pods      *pod.Manager
	converter Converter
}

func NewScanner(
	scheme *runtime.Scheme,
	clientset kubernetes.Interface,
	config Config,
	opts kube.ScannerOpts,
) *Scanner {
	return &Scanner{
		scheme:    scheme,
		config:    config,
		clientset: clientset,
		opts:      opts,
		pods:      pod.NewPodManager(clientset),
		converter: NewConverter(config),
	}
}

func (s *Scanner) Scan(ctx context.Context, workload kube.Object, gvk schema.GroupVersionKind) (v1alpha1.ConfigAuditReport, error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)

	_, owner, err := s.pods.GetPodSpecByWorkload(ctx, workload)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	klog.V(3).Infof("Scanning with options: %+v", s.opts)
	job, err := s.preparePolarisJob(workload, gvk)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	err = runner.New().Run(ctx, kube.NewRunnableJob(s.scheme, s.clientset, job))
	if err != nil {
		s.pods.LogRunnerErrors(ctx, job)
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("running polaris job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		klog.V(3).Infof("Deleting scan job: %s/%s", job.Namespace, job.Name)
		background := metav1.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", polarisContainerName,
		job.Namespace, job.Name)
	logsReader, err := s.pods.GetContainerLogsByJob(ctx, job, polarisContainerName)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("getting logs: %w", err)
	}

	result, err := s.converter.Convert(logsReader)
	defer func() {
		_ = logsReader.Close()
	}()

	return configauditreport.NewBuilder(s.scheme).
		Owner(owner).
		Result(result).
		Get()
}

func (s *Scanner) sourceNameFrom(workload kube.Object, gvk schema.GroupVersionKind) string {
	group := gvk.Group
	if len(group) > 0 {
		group = "." + group
	}
	return fmt.Sprintf("%s/%s%s/%s/%s",
		workload.Namespace,
		gvk.Kind,
		group,
		gvk.Version,
		workload.Name,
	)
}

func (s *Scanner) preparePolarisJob(workload kube.Object, gvk schema.GroupVersionKind) (*batchv1.Job, error) {
	imageRef, err := s.config.GetPolarisImageRef()
	if err != nil {
		return nil, err
	}
	sourceName := s.sourceNameFrom(workload, gvk)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: starboard.NamespaceName,
			Labels: map[string]string{
				kube.LabelResourceKind:      string(workload.Kind),
				kube.LabelResourceName:      workload.Name,
				kube.LabelResourceNamespace: workload.Namespace,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind:      string(workload.Kind),
						kube.LabelResourceName:      workload.Name,
						kube.LabelResourceNamespace: workload.Namespace,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:           starboard.ServiceAccountName,
					AutomountServiceAccountToken: pointer.BoolPtr(true),
					RestartPolicy:                corev1.RestartPolicyNever,
					Affinity:                     starboard.LinuxNodeAffinity(),
					Volumes: []corev1.Volume{
						{
							Name: configVolume,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: starboard.ConfigMapName,
									},
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:                     polarisContainerName,
							Image:                    imageRef,
							ImagePullPolicy:          corev1.PullIfNotPresent,
							TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("300m"),
									corev1.ResourceMemory: resource.MustParse("300M"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("50M"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      configVolume,
									MountPath: "/etc/starboard",
								},
							},
							Command: []string{"polaris"},
							Args: []string{"audit",
								"--log-level", "error",
								"--config", "/etc/starboard/polaris.config.yaml",
								"--resource", sourceName},
						},
					},
				},
			},
		},
	}, nil
}
