package polaris

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"k8s.io/apimachinery/pkg/runtime/schema"

	starboardv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/scanners"

	"k8s.io/utils/pointer"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"
	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/google/uuid"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	polarisContainerName = "polaris"
	configVolume         = "config"
	polarisVersion       = "1.2"
)

var (
	polarisContainerImage = fmt.Sprintf("quay.io/fairwinds/polaris:%s", polarisVersion)
)

type Scanner struct {
	scheme    *runtime.Scheme
	opts      kube.ScannerOpts
	clientset kubernetes.Interface
	pods      *pod.Manager
	converter Converter
}

func NewScanner(scheme *runtime.Scheme, opts kube.ScannerOpts, clientset kubernetes.Interface) *Scanner {
	return &Scanner{
		scheme:    scheme,
		opts:      opts,
		clientset: clientset,
		pods:      pod.NewPodManager(clientset),
		converter: DefaultConverter,
	}
}

func (s *Scanner) Scan(ctx context.Context, workload kube.Object, gvk schema.GroupVersionKind) (starboardv1alpha1.ConfigAuditReport, error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)

	_, owner, err := s.pods.GetPodSpecByWorkload(ctx, workload)
	if err != nil {
		return starboardv1alpha1.ConfigAuditReport{}, err
	}

	klog.V(3).Infof("Scanning with options: %+v", s.opts)
	job := s.preparePolarisJob(workload, gvk)

	err = runner.New().Run(ctx, kube.NewRunnableJob(s.clientset, job))
	if err != nil {
		s.pods.LogRunnerErrors(ctx, job)
		return starboardv1alpha1.ConfigAuditReport{}, fmt.Errorf("running polaris job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		klog.V(3).Infof("Deleting scan job: %s/%s", job.Namespace, job.Name)
		background := meta.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, meta.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", polarisContainerName,
		job.Namespace, job.Name)
	logsReader, err := s.pods.GetContainerLogsByJob(ctx, job, polarisContainerName)
	if err != nil {
		return starboardv1alpha1.ConfigAuditReport{}, fmt.Errorf("getting logs: %w", err)
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

func (s *Scanner) preparePolarisJob(workload kube.Object, gvk schema.GroupVersionKind) *batch.Job {
	sourceName := s.sourceNameFrom(workload, gvk)
	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: starboard.NamespaceName,
			Labels: map[string]string{
				kube.LabelResourceKind:      string(workload.Kind),
				kube.LabelResourceName:      workload.Name,
				kube.LabelResourceNamespace: workload.Namespace,
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind:      string(workload.Kind),
						kube.LabelResourceName:      workload.Name,
						kube.LabelResourceNamespace: workload.Namespace,
					},
				},
				Spec: core.PodSpec{
					ServiceAccountName:           starboard.ServiceAccountName,
					AutomountServiceAccountToken: pointer.BoolPtr(true),
					RestartPolicy:                core.RestartPolicyNever,
					Volumes: []core.Volume{
						{
							Name: configVolume,
							VolumeSource: core.VolumeSource{
								ConfigMap: &core.ConfigMapVolumeSource{
									LocalObjectReference: core.LocalObjectReference{
										Name: starboard.ConfigMapName,
									},
								},
							},
						},
					},
					Containers: []core.Container{
						{
							Name:                     polarisContainerName,
							Image:                    polarisContainerImage,
							ImagePullPolicy:          core.PullIfNotPresent,
							TerminationMessagePolicy: core.TerminationMessageFallbackToLogsOnError,
							Resources: core.ResourceRequirements{
								Limits: core.ResourceList{
									core.ResourceCPU:    resource.MustParse("300m"),
									core.ResourceMemory: resource.MustParse("300M"),
								},
								Requests: core.ResourceList{
									core.ResourceCPU:    resource.MustParse("50m"),
									core.ResourceMemory: resource.MustParse("50M"),
								},
							},
							VolumeMounts: []core.VolumeMount{
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
	}
}
