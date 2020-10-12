package trivy

import (
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/operator/etc"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/trivy"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/scanners"

	"github.com/aquasecurity/starboard/pkg/operator/scanner"
	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

type trivyScanner struct {
	config etc.ScannerTrivy
}

func NewScanner(config etc.ScannerTrivy) scanner.VulnerabilityScanner {
	return &trivyScanner{
		config: config,
	}
}

func (s *trivyScanner) NewScanJob(meta scanner.JobMeta, options scanner.Options, spec corev1.PodSpec) (*batchv1.Job, error) {
	jobName := fmt.Sprintf(uuid.New().String())

	initContainerName := jobName

	initContainers := []corev1.Container{
		{
			Name:                     initContainerName,
			Image:                    s.config.ImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Command: []string{
				"trivy",
			},
			Args: []string{
				"--download-db-only",
				"--cache-dir",
				"/var/lib/trivy",
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "data",
					ReadOnly:  false,
					MountPath: "/var/lib/trivy",
				},
			},
		},
	}

	scanJobContainers := make([]corev1.Container, len(spec.Containers))
	for i, c := range spec.Containers {
		var envs []corev1.EnvVar

		scanJobContainers[i] = corev1.Container{
			Name:                     c.Name,
			Image:                    s.config.ImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      envs,
			Command: []string{
				"trivy",
			},
			Args: []string{
				"--skip-update",
				"--cache-dir",
				"/var/lib/trivy",
				"--no-progress",
				"--format",
				"json",
				c.Image,
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("100M"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("500m"),
					corev1.ResourceMemory: resource.MustParse("500M"),
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "data",
					ReadOnly:  false,
					MountPath: "/var/lib/trivy",
				},
			},
		}
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        jobName,
			Namespace:   options.Namespace,
			Labels:      meta.Labels,
			Annotations: meta.Annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(options.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      meta.Labels,
					Annotations: meta.Annotations,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					ServiceAccountName:           options.ServiceAccountName,
					AutomountServiceAccountToken: pointer.BoolPtr(false),
					Volumes: []corev1.Volume{
						{
							Name: "data",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumDefault,
								},
							},
						},
					},
					InitContainers: initContainers,
					Containers:     scanJobContainers,
				},
			},
		},
	}, nil
}

func (s *trivyScanner) ParseVulnerabilityScanResult(imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error) {
	result, err := trivy.DefaultConverter.Convert(s.config, imageRef, logsReader)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}
	return result, nil
}
