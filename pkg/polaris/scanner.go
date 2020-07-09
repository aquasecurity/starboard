package polaris

import (
	"context"
	"fmt"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
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
	// TODO: The latest semver tagged image 0.6.0 doesn't return audit checks ?!
	polarisContainerImage = "quay.io/fairwinds/polaris:cfc0d213cd603793d8e36eecfb0def1579a34997"
	polarisConfigVolume   = "config-volume"
	polarisConfigMap      = "polaris"
)

type Scanner struct {
	opts      kube.ScannerOpts
	clientset kubernetes.Interface
	pods      *pod.Manager
	converter Converter
	scanners.Base
}

func NewScanner(opts kube.ScannerOpts, clientset kubernetes.Interface) *Scanner {
	return &Scanner{
		opts:      opts,
		clientset: clientset,
		pods:      pod.NewPodManager(clientset),
		converter: DefaultConverter,
	}
}

func (s *Scanner) Scan(ctx context.Context) (reports []starboard.ConfigAudit, err error) {
	job := s.preparePolarisJob()

	err = runner.New().Run(ctx, kube.NewRunnableJob(s.clientset, job))
	if err != nil {
		s.pods.LogRunnerErrors(ctx, job)
		err = fmt.Errorf("running polaris job: %w", err)
		return
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
		err = fmt.Errorf("getting logs: %w", err)
		return
	}

	reports, err = s.converter.Convert(logsReader)
	defer func() {
		_ = logsReader.Close()
	}()
	return
}

func (s *Scanner) preparePolarisJob() *batch.Job {
	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: kube.NamespaceStarboard,
			Labels: map[string]string{
				"app": "polaris",
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: s.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{
						"app": "polaris",
					},
				},
				Spec: core.PodSpec{
					ServiceAccountName: kube.ServiceAccountPolaris,
					RestartPolicy:      core.RestartPolicyNever,
					Volumes: []core.Volume{
						{
							Name: polarisConfigVolume,
							VolumeSource: core.VolumeSource{
								ConfigMap: &core.ConfigMapVolumeSource{
									LocalObjectReference: core.LocalObjectReference{
										Name: polarisConfigMap,
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
									core.ResourceCPU:    resource.MustParse("0.3"),
									core.ResourceMemory: resource.MustParse("300M"),
								},
								Requests: core.ResourceList{
									core.ResourceCPU:    resource.MustParse("0.05"),
									core.ResourceMemory: resource.MustParse("50M"),
								},
							},
							VolumeMounts: []core.VolumeMount{
								{
									Name:      polarisConfigVolume,
									MountPath: "/examples",
								},
							},
							Command: []string{"polaris"},
							Args:    []string{"audit", "--log-level", "error"},
						},
					},
				},
			},
		},
	}
}
