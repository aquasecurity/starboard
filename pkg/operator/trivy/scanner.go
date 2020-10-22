package trivy

import (
	"io"

	"github.com/aquasecurity/starboard/pkg/ext"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/trivy"
	"github.com/aquasecurity/starboard/pkg/operator/etc"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/operator/scanner"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/pointer"
)

type trivyScanner struct {
	idGenerator ext.IDGenerator
	config      etc.ScannerTrivy
}

// NewScanner constructs a new VulnerabilityScanner, which is using an official
// Trivy container image to scan pod containers.
func NewScanner(idGenerator ext.IDGenerator, config etc.ScannerTrivy) scanner.VulnerabilityScanner {
	return &trivyScanner{
		idGenerator: idGenerator,
		config:      config,
	}
}

func (s *trivyScanner) GetPodTemplateSpec(spec corev1.PodSpec, options scanner.Options) (corev1.PodTemplateSpec, error) {
	initContainers := []corev1.Container{
		{
			Name:                     s.idGenerator.GenerateID(),
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
		},
	}

	containers := make([]corev1.Container, len(spec.Containers))
	for i, c := range spec.Containers {
		var envs []corev1.EnvVar

		containers[i] = corev1.Container{
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

	return corev1.PodTemplateSpec{
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
			Containers:     containers,
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
