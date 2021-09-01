package conftest

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Conftest"
)

const (
	containerName        = "conftest"
	workloadKey          = "starboard.workload.yaml"
	defaultCheckCategory = "Security"
)

const (
	keyImageRef                = "conftest.imageRef"
	keyResourcesRequestsCPU    = "conftest.resources.requests.cpu"
	keyResourcesRequestsMemory = "conftest.resources.requests.memory"
	keyResourcesLimitsCPU      = "conftest.resources.limits.cpu"
	keyResourcesLimitsMemory   = "conftest.resources.limits.memory"
	keyPrefixPolicy            = "conftest.policy."
)

// Config defines configuration params for this plugin.
type Config struct {
	starboard.PluginConfig
}

// GetImageRef returns upstream Conftest container image reference.
func (c Config) GetImageRef() (string, error) {
	return c.GetRequiredData(keyImageRef)
}

// GetPolicies returns Config keys prefixed with `conftest.policy.` that define
// Rego policies.
func (c Config) GetPolicies() map[string]string {
	policies := make(map[string]string)

	for key, value := range c.Data {
		if !strings.HasPrefix(key, keyPrefixPolicy) {
			continue
		}
		if !strings.HasSuffix(key, ".rego") {
			continue
		}
		policies[key] = value
	}

	return policies
}

// GetResourceRequirements constructs ResourceRequirements from the Config.
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
			return fmt.Errorf("parsing resource definition %s: %s %v", configKey, value, err)
		}

		(*k8sResourceList)[k8sResourceName] = quantity
	}
	return nil
}

type plugin struct {
	idGenerator ext.IDGenerator
	clock       ext.Clock
}

// NewPlugin constructs a new configauditreport.Plugin, which is using
// the upstream Conftest container image to audit K8s workloads.
func NewPlugin(idGenerator ext.IDGenerator, clock ext.Clock) configauditreport.Plugin {
	return &plugin{
		idGenerator: idGenerator,
		clock:       clock,
	}
}

var (
	supportedKinds = map[kube.Kind]bool{
		kube.KindPod:                   true,
		kube.KindDeployment:            true,
		kube.KindReplicaSet:            true,
		kube.KindReplicationController: true,
		kube.KindStatefulSet:           true,
		kube.KindDaemonSet:             true,
		kube.KindCronJob:               true,
		kube.KindJob:                   true,
		kube.KindService:               true,
		kube.KindConfigMap:             true,
		kube.KindRole:                  true,
		kube.KindRoleBinding:           true,

		kube.KindClusterRole:              true,
		kube.KindClusterRoleBindings:      true,
		kube.KindCustomResourceDefinition: true,
	}
)

func (p *plugin) SupportsKind(kind kube.Kind) bool {
	return supportedKinds[kind]
}

// IsReady returns true if there is at least one policy, false otherwise.
func (p *plugin) IsReady(ctx starboard.PluginContext) (bool, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return false, err
	}
	return len(config.GetPolicies()) > 0, nil
}

func (p *plugin) Init(ctx starboard.PluginContext) error {
	return ctx.EnsureConfig(starboard.PluginConfig{
		Data: map[string]string{
			keyImageRef:                "openpolicyagent/conftest:v0.25.0",
			keyResourcesRequestsCPU:    "50m",
			keyResourcesRequestsMemory: "50M",
			keyResourcesLimitsCPU:      "300m",
			keyResourcesLimitsMemory:   "300M",
		},
	})
}

func (p *plugin) GetConfigHash(ctx starboard.PluginContext) (string, error) {
	cm, err := ctx.GetConfig()
	if err != nil {
		return "", fmt.Errorf("getting config: %w", err)
	}
	data := make(map[string]string)
	for key, value := range cm.Data {
		if strings.HasPrefix(key, "conftest.resources.") {
			continue
		}
		data[key] = value
	}
	return kube.ComputeHash(data), nil
}

func (p *plugin) GetScanJobSpec(ctx starboard.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("constructing config from plugin context: %w", err)
	}
	imageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("getting image ref: %w", err)
	}

	policies := config.GetPolicies()

	var volumeMounts []corev1.VolumeMount
	var volumeItems []corev1.KeyToPath

	secretName := configauditreport.GetScanJobName(obj) + "-volume"
	secretData := make(map[string]string)

	for policy, script := range policies {
		policyName := strings.TrimPrefix(policy, keyPrefixPolicy)

		// Copy policies so even if the starboard-conftest-config ConfigMap has changed
		// before the scan Job is run, it won't fail with references to non-existent config key error.
		secretData[policy] = script

		volumeItems = append(volumeItems, corev1.KeyToPath{
			Key:  policy,
			Path: policyName,
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      secretName,
			MountPath: "/project/policy/" + policyName,
			SubPath:   policyName,
			ReadOnly:  true,
		})

	}

	workloadAsYAML, err := yaml.Marshal(obj)
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("marshalling workload: %w", err)
	}

	secretData[workloadKey] = string(workloadAsYAML)

	volumeItems = append(volumeItems, corev1.KeyToPath{
		Key:  workloadKey,
		Path: "workload.yaml",
	})

	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      secretName,
		MountPath: "/project/workload.yaml",
		SubPath:   "workload.yaml",
		ReadOnly:  true,
	})
	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("getting resource requirements: %w", err)
	}
	return corev1.PodSpec{
			ServiceAccountName:           ctx.GetServiceAccountName(),
			AutomountServiceAccountToken: pointer.BoolPtr(false),
			RestartPolicy:                corev1.RestartPolicyNever,
			Affinity:                     starboard.LinuxNodeAffinity(),
			Volumes: []corev1.Volume{
				{
					Name: secretName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: secretName,
							Items:      volumeItems,
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:                     containerName,
					Image:                    imageRef,
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Resources:                requirements,
					VolumeMounts:             volumeMounts,
					Command: []string{
						"sh",
					},
					// TODO Follow up with Conftest maintainers to allow returning 0 exit code in case of failures
					Args: []string{
						"-c",
						"conftest test --no-fail --output json --all-namespaces --policy /project/policy /project/workload.yaml",
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               pointer.BoolPtr(false),
						AllowPrivilegeEscalation: pointer.BoolPtr(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: pointer.BoolPtr(true),
					},
				},
			},
			SecurityContext: &corev1.PodSecurityContext{},
		}, []*corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: ctx.GetNamespace(),
			},
			StringData: secretData,
		}}, nil
}

func (p *plugin) GetContainerName() string {
	return containerName
}

func (p *plugin) ParseConfigAuditReportData(ctx starboard.PluginContext, logsReader io.ReadCloser) (v1alpha1.ConfigAuditReportData, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, fmt.Errorf("constructing config from plugin context: %w", err)
	}
	var checkResults []CheckResult
	err = json.NewDecoder(logsReader).Decode(&checkResults)

	checks := make([]v1alpha1.Check, 0)
	var successesCount, warningCount, dangerCount int

	for _, cr := range checkResults {
		// Conftest reportedly returns negative count of passed tests is some cases: https://github.com/open-policy-agent/conftest/issues/464
		if cr.Successes > 0 {
			successesCount += cr.Successes
		}

		for _, warning := range cr.Warnings {
			checks = append(checks, v1alpha1.Check{
				ID:       p.getPolicyTitleFromResult(warning),
				Severity: v1alpha1.ConfigAuditSeverityWarning,
				Message:  warning.Message,
				Category: defaultCheckCategory,
				Success:  false,
			})
			warningCount++
		}

		for _, failure := range cr.Failures {
			checks = append(checks, v1alpha1.Check{
				ID:       p.getPolicyTitleFromResult(failure),
				Severity: v1alpha1.ConfigAuditSeverityDanger,
				Message:  failure.Message,
				Category: defaultCheckCategory,
			})
			dangerCount++
		}
	}

	imageRef, err := config.GetImageRef()
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, fmt.Errorf("getting image ref: %w", err)
	}

	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, fmt.Errorf("getting version from image ref: %w", err)
	}

	return v1alpha1.ConfigAuditReportData{
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Conftest",
			Vendor:  "Open Policy Agent",
			Version: version,
		},
		Summary: v1alpha1.ConfigAuditSummary{
			PassCount:    successesCount,
			WarningCount: warningCount,
			DangerCount:  dangerCount,
		},
		Checks: checks,
		// TODO Deprecate PodChecks and ContainerChecks in 0.12+
		PodChecks:       checks,
		ContainerChecks: map[string][]v1alpha1.Check{},
	}, nil
}

func (p *plugin) getPolicyTitleFromResult(result Result) string {
	if title, ok := result.Metadata["title"]; ok {
		return title.(string)
	}
	// Fallback to a unique identifier
	return p.idGenerator.GenerateID()
}

func (p *plugin) newConfigFrom(ctx starboard.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, fmt.Errorf("getting config: %w", err)
	}
	return Config{PluginConfig: pluginConfig}, nil
}
