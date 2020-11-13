package trivy

import (
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/aquasecurity/starboard/pkg/ext"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/pointer"
)

var (
	defaultResourceRequirements = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("100M"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("500M"),
		},
	}
)

type trivyScanner struct {
	idGenerator ext.IDGenerator
	config      starboard.TrivyConfig
}

// NewScanner constructs a new vulnerabilityreport.Scanner, which is using an official
// Trivy container image to scan Kubernetes workloads.
//
// This vulnerabilityreport.Scanner supports both trivy.Standalone and trivy.ClientServer
// client modes depending on the current starboard.TrivyConfig.
//
// The trivy.ClientServer more is usually more performant, however it requires a Trivy server
// to be hosted and accessible at the configurable URL.
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

// In the Standalone mode there is the init container responsible for downloading
// the latest Trivy DB file from GitHub and storing it to the empty volume shared
// with main containers. In other words, the init container runs the following
// Trivy command:
//
// trivy --download-db-only --cache-dir /var/lib/trivy
//
// The number of main containers correspond to the number of containers
// defined for the scanned workload. What's more, each container runs the Trivy
// scan command and skips the database update:
//
// trivy --skip-update --cache-dir /var/lib/trivy --format json <container image>
func (s *trivyScanner) getPodSpecForStandaloneMode(spec corev1.PodSpec) (corev1.PodSpec, error) {
	initContainer := corev1.Container{
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
		Resources: defaultResourceRequirements,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/var/lib/trivy",
				ReadOnly:  false,
			},
		},
	}

	var containers []corev1.Container

	for _, c := range spec.Containers {
		containers = append(containers, corev1.Container{
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
			Resources: defaultResourceRequirements,
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "data",
					ReadOnly:  false,
					MountPath: "/var/lib/trivy",
				},
			},
		})
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
		InitContainers: []corev1.Container{initContainer},
		Containers:     containers,
	}, nil
}

// In the ClientServer mode the number of containers of the pod created by the scan job
// equals the number of containers defined for the scanned workload.
// Each container runs Trivy scan command pointing to a remote Trivy server:
//
// trivy client --remote http://trivy-server.trivy-server:4954 --format json <container image>
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
			Resources: defaultResourceRequirements,
		})
	}
	return corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Containers:                   containers,
	}, nil
}

func (s *trivyScanner) ParseVulnerabilityScanResult(imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error) {
	result, err := DefaultConverter.Convert(s.config, imageRef, logsReader)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}
	return result, nil
}
