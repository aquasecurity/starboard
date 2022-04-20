package grype

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Grype"
)

const (
	keyGrypeImageRef       = "grype.imageRef"
	keyGrypeScheme         = "grype.scheme"
	keyGrypePath           = "grype.path"
	keyGrypeOnlyFixed      = "grype.onlyFixed"
	keyGrypeExcludePaths   = "grype.exclude"
	keyGrypeHTTPProxy      = "grype.httpProxy"
	keyGrypeHTTPSProxy     = "grype.httpsProxy"
	keyGrypeNoProxy        = "grype.noProxy"
	keyGrypeUpdateURL      = "grype.updateURL"
	keyGrypeAddMissingCPEs = "grype.addMissingCPEs"
	keyGrypeRegAuthority   = "grype.regAuthority"

	keyResourcesRequestsCPU    = "grype.resources.requests.cpu"
	keyResourcesRequestsMemory = "grype.resources.requests.memory"
	keyResourcesLimitsCPU      = "grype.resources.limits.cpu"
	keyResourcesLimitsMemory   = "grype.resources.limits.memory"
)

const defaultUpdateURL = "https://toolbox-data.anchore.io/grype/databases/listing.json"

// Config defines configuration params for this plugin.
type Config struct {
	starboard.PluginConfig
}

// GetResourceRequirements creates ResourceRequirements from the Config.
func (c Config) GetResourceRequirements() (corev1.ResourceRequirements, error) {
	requirements := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	err := c.setResourceLimit(keyResourcesRequestsCPU, &requirements.Requests, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesRequestsMemory, &requirements.Requests, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsCPU, &requirements.Limits, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsMemory, &requirements.Limits, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	return requirements, nil
}

func (c Config) setResourceLimit(configKey string, k8sResourceList *corev1.ResourceList, k8sResourceName corev1.ResourceName) error {
	if value, found := c.Data[configKey]; found {
		quantity, err := resource.ParseQuantity(value)
		if err != nil {
			return fmt.Errorf("parsing resource definition %s: %s %w", configKey, value, err)
		}

		(*k8sResourceList)[k8sResourceName] = quantity
	}
	return nil
}

func (c *Config) GetImageRef() (string, error) {
	return c.GetRequiredData(keyGrypeImageRef)
}

type plugin struct {
	clock          ext.Clock
	idGenerator    ext.IDGenerator
	objectResolver *kube.ObjectResolver
}

// NewPlugin constructs a new vulnerabilityreport.Plugin, which is using an
// upstream Grype container image to scan Kubernetes workloads.
//
// The plugin supports Image and Filesystem commands. The Filesystem command may
// be used to scan workload images cached on cluster nodes by scheduling
// scan jobs on a particular node.
//
// The Image command supports both Standalone and ClientServer modes depending
// on the settings returned by Config.GetMode. The ClientServer mode is usually
// more performant, however it requires a Grype server accessible at the
// configurable Config.GetServerURL.
func NewPlugin(clock ext.Clock, idGenerator ext.IDGenerator, client client.Client) vulnerabilityreport.Plugin {
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: &kube.ObjectResolver{Client: client},
	}
}

// Init ensures the default Config required by this plugin.
func (p *plugin) Init(ctx starboard.PluginContext) error {
	return ctx.EnsureConfig(starboard.PluginConfig{
		Data: map[string]string{
			keyGrypeImageRef:  "anchore/grype:0.34.7",
			keyGrypeUpdateURL: defaultUpdateURL,

			keyResourcesRequestsCPU:    "100m",
			keyResourcesRequestsMemory: "100M",
			keyResourcesLimitsCPU:      "500m",
			keyResourcesLimitsMemory:   "500M",
		},
	})
}

func (p *plugin) GetScanJobSpec(ctx starboard.PluginContext, workload client.Object, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	return p.getPodSpec(ctx, config, workload, credentials)
}

func (p *plugin) newSecretWithAggregateImagePullCredentials(obj client.Object, spec corev1.PodSpec, credentials map[string]docker.Auth) *corev1.Secret {
	containerImages := kube.GetContainerImagesFromPodSpec(spec)
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: vulnerabilityreport.RegistryCredentialsSecretName(obj),
		},
		Data: secretData,
	}
}

const (
	tmpVolumeName        = "tmp"
	ignoreFileVolumeName = "ignorefile"
	FsSharedVolumeName   = "starboard"
	grypeDBLocation      = "/tmp/grypedb"
)

// There is an init container to cache the Grype DB, which will be stored in an
// emptyDir volume and shared across the scanning containers. Most configuration
// is done via the environment of the scanning containers
//
//     grype db update
//
// The number of main containers correspond to the number of containers
// defined for the scanned workload. Each container runs the Grype image scan
// command and skips the database download:
//
//     grype <container image> --skip-update --quiet --output json
func (p *plugin) getPodSpec(ctx starboard.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret

	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	if len(credentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, spec, credentials)
		secrets = append(secrets, secret)
	}

	grypeImageRef, err := config.GetRequiredData(keyGrypeImageRef)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	grypeConfigName := starboard.GetPluginConfigMapName(Plugin)

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      tmpVolumeName,
			ReadOnly:  false,
			MountPath: grypeDBLocation,
		},
	}
	volumes := []corev1.Volume{
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}

	commonEnv := []corev1.EnvVar{
		{
			Name: "HTTP_PROXY",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: grypeConfigName,
					},
					Key:      keyGrypeHTTPProxy,
					Optional: pointer.BoolPtr(true),
				},
			},
		},
		{
			Name: "HTTPS_PROXY",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: grypeConfigName,
					},
					Key:      keyGrypeHTTPSProxy,
					Optional: pointer.BoolPtr(true),
				},
			},
		},
		{
			Name: "NO_PROXY",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: grypeConfigName,
					},
					Key:      keyGrypeNoProxy,
					Optional: pointer.BoolPtr(true),
				},
			},
		},
		{
			Name: "GRYPE_DB_UPDATE_URL",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: grypeConfigName,
					},
					Key:      keyGrypeUpdateURL,
					Optional: pointer.BoolPtr(false),
				},
			},
		},
		{
			Name:  "GRYPE_DB_CACHE_DIR",
			Value: grypeDBLocation,
		},
	}

	initContainer := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    grypeImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env:                      commonEnv,
		Command: []string{
			"grype",
		},
		Args: []string{
			"db",
			"update",
		},
		Resources:    requirements,
		VolumeMounts: volumeMounts,
	}

	var containers []corev1.Container

	for _, c := range spec.Containers {

		//optionally add schema
		scanImage := ""
		if val, ok := config.Data[keyGrypeScheme]; ok {
			scanImage = val + ":" + c.Image
		} else {
			scanImage = c.Image
		}

		env := append(commonEnv,
			corev1.EnvVar{
				Name: "GRYPE_REGISTRY_AUTH_AUTHORITY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: grypeConfigName,
						},
						Key:      keyGrypeRegAuthority,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			corev1.EnvVar{
				Name: "GRYPE_EXCLUDE",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: grypeConfigName,
						},
						Key:      keyGrypeExcludePaths,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			corev1.EnvVar{
				Name:  "GRYPE_DB_AUTO_UPDATE",
				Value: "false",
			},
		)

		if _, ok := credentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)

			env = append(env, corev1.EnvVar{
				Name: "GRYPE_REGISTRY_AUTH_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryUsernameKey,
					},
				},
			}, corev1.EnvVar{
				Name: "GRYPE_REGISTRY_AUTH_PASSWORD",
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

		// env, err = p.appendGrypeInsecureEnv(config, c.Image, env)
		// if err != nil {
		// 	return corev1.PodSpec{}, nil, err
		// }

		// env, err = p.appendGrypeNonSSLEnv(config, c.Image, env)
		// if err != nil {
		// 	return corev1.PodSpec{}, nil, err
		// }

		args := []string{
			scanImage,
			"--skip-update",
			"--quiet",
			"--output",
			"json",
		}

		if args, err = p.appendGrypeOptionalArg(config, args, "--add-cpes-if-none", keyGrypeAddMissingCPEs); err != nil {
			return corev1.PodSpec{}, nil, err
		}
		if args, err = p.appendGrypeOptionalArg(config, args, "--only-fixed", keyGrypeOnlyFixed); err != nil {
			return corev1.PodSpec{}, nil, err
		}

		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    grypeImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				"grype",
			},
			Args:         args,
			Resources:    requirements,
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
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainer},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, secrets, nil
}

func (p *plugin) appendGrypeOptionalArg(config Config, args []string, arg string, key string) ([]string, error) {
	if val, ok := config.Data[key]; ok && val == "true" {
		return append(args, arg), nil
	} else if !ok {
		//ignore if optional key is not in config.data
		return args, nil
	} else {
		return args, nil
	}
}

// func (p *plugin) appendGrypeInsecureEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
// 	ref, err := name.ParseReference(image)
// 	if err != nil {
// 		return nil, err
// 	}

// 	insecureRegistries := config.GetInsecureRegistries()
// 	if insecureRegistries[ref.Context().RegistryStr()] {
// 		env = append(env, corev1.EnvVar{
// 			Name:  "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY",
// 			Value: "true",
// 		})
// 	}

// 	return env, nil
// }

// func (p *plugin) appendGrypeNonSSLEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
// 	ref, err := name.ParseReference(image)
// 	if err != nil {
// 		return nil, err
// 	}

// 	nonSSLRegistries := config.GetNonSSLRegistries()
// 	if nonSSLRegistries[ref.Context().RegistryStr()] {
// 		env = append(env, corev1.EnvVar{
// 			Name:  "GRYPE_REGISTRY_INSECURE_USE_HTTP",
// 			Value: "true",
// 		})
// 	}

// 	return env, nil
// }

func (p *plugin) ParseVulnerabilityReportData(ctx starboard.PluginContext, imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}
	var report ScanReport
	err = json.NewDecoder(logsReader).Decode(&report)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)

	for _, match := range report.Matches {
		vul := match.Vulnerability
		artifact := match.Artifact

		fixVersion := ""
		for _, version := range match.Vulnerability.Fix.Versions {
			fixVersion += version
			fixVersion += ", "
		}
		fixVersion = strings.TrimSuffix(fixVersion, ", ")

		var score *float64 = pointer.Float64Ptr(0)
		for _, cvs := range vul.CVSs {
			if matched, err := regexp.MatchString("3\\..*", cvs.Version); matched && err == nil {
				score = cvs.Metrics.BaseScore
			}
		}

		var severity v1alpha1.Severity
		if severity, err = v1alpha1.StringToSeverity(vul.Severity); err != nil {
			severity = v1alpha1.Severity("UNKNOWN")
		}

		vulnerabilities = append(vulnerabilities, v1alpha1.Vulnerability{
			VulnerabilityID:  vul.Id,
			Resource:         artifact.Name,
			InstalledVersion: artifact.Version,
			FixedVersion:     fixVersion,
			Severity:         severity,
			Title:            artifact.Name,
			PrimaryLink:      vul.DataSource,
			Description:      vul.Description,
			Links:            vul.URLs,
			Score:            score,
		})
	}

	registry, artifact, err := p.parseImageRef(imageRef)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	grypeImageRef, err := config.GetRequiredData(keyGrypeImageRef)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	version, err := starboard.GetVersionFromImageRef(grypeImageRef)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	return v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Grype",
			Vendor:  "Anchore Inc.",
			Version: version,
		},
		Registry:        registry,
		Artifact:        artifact,
		Summary:         p.toSummary(vulnerabilities),
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (p *plugin) newConfigFrom(ctx starboard.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

func (p *plugin) toSummary(vulnerabilities []v1alpha1.Vulnerability) v1alpha1.VulnerabilitySummary {
	var vs v1alpha1.VulnerabilitySummary
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
	return vs
}

func (p *plugin) parseImageRef(imageRef string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
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

func constructEnvVarSourceFromConfigMap(envName, configName, configKey string) (res corev1.EnvVar) {
	res = corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: configName,
				},
				Key:      configKey,
				Optional: pointer.BoolPtr(true),
			},
		},
	}
	return
}
