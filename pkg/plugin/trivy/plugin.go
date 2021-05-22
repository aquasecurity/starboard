package trivy

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/docker"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"github.com/google/go-containerregistry/pkg/name"
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

// TODO Rename scanner struct to plugin.
type scanner struct {
	clock       ext.Clock
	idGenerator ext.IDGenerator
	config      Config
}

// Config defines configuration params for the Trivy vulnerabilityreport.Plugin.
type Config interface {
	GetTrivyImageRef() (string, error)
	GetTrivyMode() (starboard.TrivyMode, error)
	GetTrivyServerURL() (string, error)
	GetTrivyInsecureRegistries() map[string]bool
	TrivyIgnoreFileExists() bool
}

// NewPlugin constructs a new vulnerabilityreport.Plugin, which is using an
// official Trivy container image to scan Kubernetes workloads.
//
// This Plugin supports both starboard.Standalone and starboard.ClientServer
// client modes depending on the active mode returned by Config.GetTrivyMode.
//
// The starboard.ClientServer mode is usually more performant, however it
// requires a Trivy server accessible at the configurable URL.
func NewPlugin(clock ext.Clock, idGenerator ext.IDGenerator, config Config) vulnerabilityreport.Plugin {
	return &scanner{
		clock:       clock,
		idGenerator: idGenerator,
		config:      config,
	}
}

func (s *scanner) GetScanJobSpec(spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	mode, err := s.config.GetTrivyMode()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	switch mode {
	case starboard.Standalone:
		return s.getPodSpecForStandaloneMode(spec, credentials)
	case starboard.ClientServer:
		return s.getPodSpecForClientServerMode(spec, credentials)
	default:
		return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized trivy mode: %v", mode)
	}
}

func (s *scanner) newSecretWithAggregateImagePullCredentials(spec corev1.PodSpec, credentials map[string]docker.Auth) *corev1.Secret {
	containerImages := kube.GetContainerImagesFromPodSpec(spec)
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.idGenerator.GenerateID(),
		},
		Data: secretData,
	}
}

const (
	sharedVolumeName     = "data"
	ignoreFileVolumeName = "ignorefile"
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
func (s *scanner) getPodSpecForStandaloneMode(spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret

	if len(credentials) > 0 {
		secret = s.newSecretWithAggregateImagePullCredentials(spec, credentials)
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

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      sharedVolumeName,
			ReadOnly:  false,
			MountPath: "/var/lib/trivy",
		},
	}
	volumes := []corev1.Volume{
		{
			Name: sharedVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}

	if s.config.TrivyIgnoreFileExists() {
		volumes = append(volumes, corev1.Volume{
			Name: ignoreFileVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: starboard.ConfigMapName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "trivy.ignoreFile",
							Path: ".trivyignore",
						},
					},
				},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      ignoreFileVolumeName,
			MountPath: "/tmp/trivy/.trivyignore",
			SubPath:   ".trivyignore",
		})
	}

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
				Name: "TRIVY_IGNORE_UNFIXED",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.ignoreUnfixed",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SKIP_FILES",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.skipFiles",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SKIP_DIRS",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.skipDirs",
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

		if s.config.TrivyIgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNOREFILE",
				Value: "/tmp/trivy/.trivyignore",
			})
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

		env, err = s.appendTrivyInsecureEnv(c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
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
			Resources:    defaultResourceRequirements,
			VolumeMounts: volumeMounts,
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
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainer},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, secrets, nil
}

// In the starboard.ClientServer mode the number of containers of the pod
// created by the scan job equals the number of containers defined for the
// scanned workload. Each container runs Trivy image scan command and refers
// to Trivy server URL returned by Config.GetTrivyServerURL:
//
//     trivy client --remote <server URL> \
//       --format json <container image ref>
func (s *scanner) getPodSpecForClientServerMode(spec corev1.PodSpec, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var volumeMounts []corev1.VolumeMount
	var volumes []corev1.Volume

	trivyImageRef, err := s.config.GetTrivyImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	trivyServerURL, err := s.config.GetTrivyServerURL()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	if len(credentials) > 0 {
		secret = s.newSecretWithAggregateImagePullCredentials(spec, credentials)
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
				Name: "TRIVY_IGNORE_UNFIXED",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.ignoreUnfixed",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SKIP_FILES",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.skipFiles",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SKIP_DIRS",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.skipDirs",
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

		env, err = s.appendTrivyInsecureEnv(container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if s.config.TrivyIgnoreFileExists() {
			volumes = []corev1.Volume{
				{
					Name: ignoreFileVolumeName,
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: starboard.ConfigMapName,
							},
							Items: []corev1.KeyToPath{
								{
									Key:  "trivy.ignoreFile",
									Path: ".trivyignore",
								},
							},
						},
					},
				},
			}

			volumeMounts = []corev1.VolumeMount{
				{
					Name:      ignoreFileVolumeName,
					MountPath: "/tmp/trivy/.trivyignore",
					SubPath:   ".trivyignore",
				},
			}

			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNOREFILE",
				Value: "/tmp/trivy/.trivyignore",
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
				"--quiet",
				"client",
				"--format",
				"json",
				"--remote",
				trivyServerURL,
				container.Image,
			},
			VolumeMounts: volumeMounts,
			Resources:    defaultResourceRequirements,
		})
	}

	return corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Containers:                   containers,
		Volumes:                      volumes,
	}, secrets, nil
}

func (s *scanner) appendTrivyInsecureEnv(image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	insecureRegistries := s.config.GetTrivyInsecureRegistries()
	if insecureRegistries[ref.Context().RegistryStr()] {
		env = append(env, corev1.EnvVar{
			Name:  "TRIVY_INSECURE",
			Value: "true",
		})
	}

	return env, nil
}

func (s *scanner) ParseVulnerabilityScanResult(imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error) {
	var reports []ScanReport
	err := json.NewDecoder(logsReader).Decode(&reports)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)

	for _, report := range reports {
		for _, sr := range report.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, v1alpha1.Vulnerability{
				VulnerabilityID:  sr.VulnerabilityID,
				Resource:         sr.PkgName,
				InstalledVersion: sr.InstalledVersion,
				FixedVersion:     sr.FixedVersion,
				Severity:         sr.Severity,
				Title:            sr.Title,
				PrimaryLink:      sr.PrimaryURL,
				Links:            []string{},
				Score:            GetScoreFromCVSS(sr.Cvss),
			})
		}
	}

	registry, artifact, err := s.parseImageRef(imageRef)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	trivyImageRef, err := s.config.GetTrivyImageRef()
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	version, err := starboard.GetVersionFromImageRef(trivyImageRef)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	return v1alpha1.VulnerabilityScanResult{
		UpdateTimestamp: metav1.NewTime(s.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: version,
		},
		Registry:        registry,
		Artifact:        artifact,
		Summary:         s.toSummary(vulnerabilities),
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (s *scanner) toSummary(vulnerabilities []v1alpha1.Vulnerability) (vs v1alpha1.VulnerabilitySummary) {
	for _, v := range vulnerabilities {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			vs.CriticalCount++
		case v1alpha1.SeverityHigh:
			vs.HighCount++
		case v1alpha1.SeverityMedium:
			vs.MediumCount++
		case v1alpha1.SeverityLow:
			vs.LowCount++
		default:
			vs.UnknownCount++
		}
	}
	return
}

// TODO check if it works if both tag and digest are specified
func (s *scanner) parseImageRef(imageRef string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return v1alpha1.Registry{}, v1alpha1.Artifact{}, err
	}
	registry := v1alpha1.Registry{
		Server: ref.Context().RegistryStr(),
	}
	artifact := v1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case name.Tag:
		artifact.Tag = t.TagStr()
	case name.Digest:
		artifact.Digest = t.DigestStr()
	}

	return registry, artifact, nil
}

func GetScoreFromCVSS(CVSSs map[string]*CVSS) *float64 {
	var nvdScore, vendorScore *float64

	for name, cvss := range CVSSs {
		if name == "nvd" {
			nvdScore = cvss.V3Score
		} else {
			vendorScore = cvss.V3Score
		}
	}

	if vendorScore != nil {
		return vendorScore
	}

	return nvdScore
}
