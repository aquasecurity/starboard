package trivy

import (
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/aquasecurity/starboard/pkg/ext"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/trivy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/pointer"
)

type trivyScanner struct {
	idGenerator ext.IDGenerator
	config      starboard.TrivyConfig
}

// NewScanner constructs a new VulnerabilityScanner, which is using an official
// Trivy container image to scan pod containers.
func NewScanner(idGenerator ext.IDGenerator, config starboard.TrivyConfig) vulnerabilityreport.Scanner {
	return &trivyScanner{
		idGenerator: idGenerator,
		config:      config,
	}
}

func (s *trivyScanner) GetPodSpec(spec corev1.PodSpec) (corev1.PodSpec, error) {
	switch s.config.GetTrivyMode() {
	case starboard.Standalone:
		return s.getPodSpecForStandaloneMode(spec)
	case starboard.ClientServer:
		return s.getPodSpecForClientServerMode(spec)
	default:
		return corev1.PodSpec{}, fmt.Errorf("unrecognized trivy mode: %v", s.config.GetTrivyMode())
	}
}

// In Standalone mode we have an init container that is responsible for downloading
// Trivy DB file and stored it to empty volume shared with the main containers.
// Note that then umber of the main containers corresponds to the number of containers
// of the scanner workload.
// trivy --download-db-only --cache-dir /var/lib/trivy
// trivy --skip-update --cache-dir /var/lib/trivy --no-progress --format json <container image>
func (s *trivyScanner) getPodSpecForStandaloneMode(spec corev1.PodSpec) (corev1.PodSpec, error) {
	initContainers := []corev1.Container{
		{
			Name:                     s.idGenerator.GenerateID(),
			Image:                    s.config.GetTrivyImageRef(),
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env: []corev1.EnvVar{
				{
					Name: "HTTP_PROXY",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: starboard.ConfigMapName,
							},
							Key:      "trivy.httpProxy",
							Optional: pointer.BoolPtr(true),
						},
					},
				},
				{
					Name: "GITHUB_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: starboard.ConfigMapName,
							},
							Key:      "trivy.githubToken",
							Optional: pointer.BoolPtr(true),
						},
					},
				},
			},
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

		containers[i] = corev1.Container{
			Name:                     c.Name,
			Image:                    s.config.GetTrivyImageRef(),
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env: []corev1.EnvVar{
				{
					Name: "TRIVY_SEVERITY",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: starboard.ConfigMapName,
							},
							Key:      "trivy.severity",
							Optional: pointer.BoolPtr(true),
						},
					},
				},
				{
					Name: "HTTP_PROXY",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: starboard.ConfigMapName,
							},
							Key:      "trivy.httpProxy",
							Optional: pointer.BoolPtr(true),
						},
					},
				},
			},
			Command: []string{
				"trivy",
			},
			Args: []string{
				"--skip-update",
				"--cache-dir",
				"/var/lib/trivy",
				"--quiet",
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

	return corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
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
	}, nil
}

// / # trivy client --format json --token ABC --remote http://trivy-server.trivy-server:4954 wordpress:5.5
func (s *trivyScanner) getPodSpecForClientServerMode(spec corev1.PodSpec) (corev1.PodSpec, error) {
	var containers []corev1.Container
	for _, container := range spec.Containers {
		containers = append(containers, corev1.Container{
			Name:            container.Name,
			Image:           s.config.GetTrivyImageRef(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Env: []corev1.EnvVar{
				{
					Name: "TRIVY_SEVERITY",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: starboard.ConfigMapName,
							},
							Key:      "trivy.severity",
							Optional: pointer.BoolPtr(true),
						},
					},
				},
			},
			Command: []string{
				"trivy",
			},
			Args: []string{
				"client",
				"--quiet",
				"--format",
				"json",
				"--remote",
				s.config.GetTrivyServerURL(),
				container.Image,
			},
		})
	}
	return corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Containers:                   containers,
	}, nil
}

func (s *trivyScanner) ParseVulnerabilityScanResult(imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error) {
	result, err := trivy.DefaultConverter.Convert(s.config, imageRef, logsReader)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}
	return result, nil
}
