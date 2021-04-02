package trivy

import (
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/docker"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
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
	config      Config
	converter   Converter
}

// Config defines configuration params for the Trivy vulnerabilityreport.Plugin.
type Config interface {
	GetTrivyImageRef() (string, error)
	GetTrivyMode() (starboard.TrivyMode, error)
	GetTrivyServerURL() (string, error)
}

// NewPlugin constructs a new vulnerabilityreport.Plugin, which is using an
// official Trivy container image to scan Kubernetes workloads.
//
// This Plugin supports both starboard.Standalone and starboard.ClientServer
// client modes depending on the active mode returned by Config.GetTrivyMode.
//
// The starboard.ClientServer mode is usually more performant, however it
// requires a Trivy server accessible at the configurable URL.
func NewPlugin(idGenerator ext.IDGenerator, config Config) vulnerabilityreport.Plugin {
	return &scanner{
		idGenerator: idGenerator,
		config:      config,
		converter:   NewConverter(config),
	}
}

func (s *scanner) GetScanJobSpec(ctx starboard.PluginContext, spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	mode, err := s.config.GetTrivyMode()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	switch mode {
	case starboard.Standalone:
		return s.getPodSpecForStandaloneMode(ctx, spec, credentials)
	case starboard.ClientServer:
		return s.getPodSpecForClientServerMode(ctx, spec, credentials)
	default:
		return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized trivy mode: %v", mode)
	}
}

func (s *scanner) newSecretWithAggregateImagePullCredentials(ctx starboard.PluginContext, spec corev1.PodSpec, credentials map[string]docker.Auth) *corev1.Secret {
	containerImages := kube.GetContainerImagesFromPodSpec(spec)
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.idGenerator.GenerateID(),
			Namespace: ctx.GetNamespace(),
		},
		Data: secretData,
	}
}

const (
	sharedVolumeName = "data"
)

// In the starboard.Standalone mode there is the init container responsible for
// downloading the latest Trivy DB file from GitHub and storing it to the empty
// volume shared with main containers. In other words, the init container runs
// the following Trivy command:
//
//     trivy --download-db-only --cache-dir /var/lib/trivy
//
// The number of main containers correspond to the number of containers
// defined for the scanned workload. Each container runs the Trivy image scan
// command and skips the database download:
//
//     trivy --skip-update --cache-dir /var/lib/trivy \
//       --format json <container image>
func (s *scanner) getPodSpecForStandaloneMode(ctx starboard.PluginContext, spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret

	if len(credentials) > 0 {
		secret = s.newSecretWithAggregateImagePullCredentials(ctx, spec, credentials)
		secrets = append(secrets, secret)
	}

	trivyImageRef, err := s.config.GetTrivyImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	initContainer := corev1.Container{
		Name:                     s.idGenerator.GenerateID(),
		Image:                    trivyImageRef,
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
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.httpsProxy",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.noProxy",
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
			{
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.httpsProxy",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.noProxy",
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
			Image:                    trivyImageRef,
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
			SecurityContext: &corev1.SecurityContext{
				Privileged:               pointer.BoolPtr(false),
				AllowPrivilegeEscalation: pointer.BoolPtr(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: pointer.BoolPtr(true),
			},
		})
	}

	return corev1.PodSpec{
		Affinity:                     starboard.LinuxNodeAffinity(),
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
		SecurityContext: &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(1000),
			RunAsGroup: pointer.Int64Ptr(1000),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
	}, secrets, nil
}

// In the starboard.ClientServer mode the number of containers of the pod
// created by the scan job equals the number of containers defined for the
// scanned workload. Each container runs Trivy image scan command and refers
// to Trivy server URL returned by Config.GetTrivyServerURL:
//
//     trivy client --remote <server URL> \
//       --format json <container image ref>
func (s *scanner) getPodSpecForClientServerMode(ctx starboard.PluginContext, spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret

	trivyImageRef, err := s.config.GetTrivyImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	trivyServerURL, err := s.config.GetTrivyServerURL()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	if len(credentials) > 0 {
		secret = s.newSecretWithAggregateImagePullCredentials(ctx, spec, credentials)
		secrets = append(secrets, secret)
	}

	var containers []corev1.Container

	for _, container := range spec.Containers {

		env := []corev1.EnvVar{
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
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.httpsProxy",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.noProxy",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
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
				Name: "TRIVY_TOKEN_HEADER",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.SecretName,
						},
						Key:      "trivy.serverTokenHeader",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.SecretName,
						},
						Key:      "trivy.serverToken",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_CUSTOM_HEADERS",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.SecretName,
						},
						Key:      "trivy.serverCustomHeaders",
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
			Image:                    trivyImageRef,
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
				trivyServerURL,
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
