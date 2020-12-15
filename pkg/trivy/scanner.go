package trivy

import (
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/docker"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/resources"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

type scanner struct {
	idGenerator ext.IDGenerator
	config      starboard.TrivyConfig
	converter   Converter
}

// NewScanner constructs a new Plugin, which is using an official
// Trivy container image to scan Kubernetes workloads.
//
// This Plugin supports both starboard.Standalone and starboard.ClientServer
// client modes depending on the current starboard.TrivyConfig.
//
// The starboard.ClientServer more is usually more performant, however it
// requires a Trivy server to be hosted and accessible at the configurable URL.
func NewScannerPlugin(idGenerator ext.IDGenerator, config starboard.TrivyConfig) vulnerabilityreport.Plugin {
	return &scanner{
		idGenerator: idGenerator,
		config:      config,
		converter:   NewConverter(config),
	}
}

func (s *scanner) GetScanJobSpec(spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	switch s.config.GetTrivyMode() {
	case starboard.Standalone:
		return s.getPodSpecForStandaloneMode(spec, credentials)
	case starboard.ClientServer:
		return s.getPodSpecForClientServerMode(spec, credentials)
	default:
		return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized trivy mode: %v", s.config.GetTrivyMode())
	}
}

func (s *scanner) newSecretWithAggregateImagePullCredentials(spec corev1.PodSpec, credentials map[string]docker.Auth) *corev1.Secret {
	containerImages := resources.GetContainerImagesFromPodSpec(spec)
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.idGenerator.GenerateID(),
		},
		Data: secretData,
	}
}

const (
	sharedVolumeName = "data"
)

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
func (s *scanner) getPodSpecForStandaloneMode(spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret

	if len(credentials) > 0 {
		secret = s.newSecretWithAggregateImagePullCredentials(spec, credentials)
		secrets = append(secrets, secret)
	}

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
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.SecretName,
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
				Name:      sharedVolumeName,
				MountPath: "/var/lib/trivy",
				ReadOnly:  false,
			},
		},
	}

	var containers []corev1.Container

	for _, c := range spec.Containers {

		env := []corev1.EnvVar{
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
		}

		if _, ok := credentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)

			env = append(env, corev1.EnvVar{
				Name: "TRIVY_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryUsernameKey,
					},
				},
			}, corev1.EnvVar{
				Name: "TRIVY_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryPasswordKey,
					},
				},
			})
		}

		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    s.config.GetTrivyImageRef(),
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
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
					Name:      sharedVolumeName,
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
				Name: sharedVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumDefault,
					},
				},
			},
		},
		InitContainers: []corev1.Container{initContainer},
		Containers:     containers,
	}, secrets, nil
}

// In the ClientServer mode the number of containers of the pod created by the scan job
// equals the number of containers defined for the scanned workload.
// Each container runs Trivy scan command pointing to a remote Trivy server:
//
// trivy client --remote http://trivy-server.trivy-server:4954 --format json <container image>
func (s *scanner) getPodSpecForClientServerMode(spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret

	if len(credentials) > 0 {
		secret = s.newSecretWithAggregateImagePullCredentials(spec, credentials)
		secrets = append(secrets, secret)
	}

	var containers []corev1.Container

	for _, container := range spec.Containers {

		env := []corev1.EnvVar{
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
		}

		if _, ok := credentials[container.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", container.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", container.Name)

			env = append(env, corev1.EnvVar{
				Name: "TRIVY_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryUsernameKey,
					},
				},
			}, corev1.EnvVar{
				Name: "TRIVY_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryPasswordKey,
					},
				},
			})
		}

		containers = append(containers, corev1.Container{
			Name:                     container.Name,
			Image:                    s.config.GetTrivyImageRef(),
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
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
	}, secrets, nil
}

func (s *scanner) ParseVulnerabilityScanResult(imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error) {
	result, err := s.converter.Convert(imageRef, logsReader)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}
	return result, nil
}
