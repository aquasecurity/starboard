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
	conftestContainerName = "conftest"
	policyPrefix          = "conftest.policy."
	workloadKey           = "starboard.workload.yaml"
	defaultCheckCategory  = "Security"
)

type Config interface {
	GetConftestImageRef() (string, error)
}

type plugin struct {
	idGenerator ext.IDGenerator
	clock       ext.Clock
	config      Config
}

// NewPlugin constructs a new configauditreport.Plugin, which is using
// the upstream Conftest container image to audit K8s workloads.
func NewPlugin(idGenerator ext.IDGenerator, clock ext.Clock, config Config) configauditreport.Plugin {
	return &plugin{
		idGenerator: idGenerator,
		clock:       clock,
		config:      config,
	}
}

func (p *plugin) GetConfigHash(ctx starboard.PluginContext) (string, error) {
	cm, err := ctx.GetConfig()
	if err != nil {
		return "", err
	}
	return kube.ComputeHash(cm.Data), nil
}

func (p *plugin) GetScanJobSpec(ctx starboard.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	imageRef, err := p.config.GetConftestImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("getting image reference: %w", err)
	}

	config, err := ctx.GetConfig()
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("getting config: %w", err)
	}

	policies := p.getPolicies(config)

	var volumeMounts []corev1.VolumeMount
	var volumeItems []corev1.KeyToPath

	secretName := configauditreport.GetScanJobName(obj) + "-volume"
	secretData := make(map[string]string)

	for policy, script := range policies {
		policyName := strings.TrimPrefix(policy, policyPrefix)

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
					Name:                     conftestContainerName,
					Image:                    imageRef,
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("300m"),
							corev1.ResourceMemory: resource.MustParse("300M"),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("50m"),
							corev1.ResourceMemory: resource.MustParse("50M"),
						},
					},
					VolumeMounts: volumeMounts,
					Command: []string{
						"sh",
					},
					// TODO Follow up with Conftest maintainers to allow returning 0 exit code in case of failures
					Args: []string{
						"-c",
						"conftest test --output json --all-namespaces --policy /project/policy /project/workload.yaml || true",
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

func (p *plugin) getPolicies(cm *corev1.ConfigMap) map[string]string {
	policies := make(map[string]string)

	for key, value := range cm.Data {
		if !strings.HasPrefix(key, policyPrefix) {
			continue
		}
		if !strings.HasSuffix(key, ".rego") {
			continue
		}
		policies[key] = value
	}

	return policies
}

func (p *plugin) GetContainerName() string {
	return conftestContainerName
}

func (p *plugin) ParseConfigAuditReportData(logsReader io.ReadCloser) (v1alpha1.ConfigAuditResult, error) {
	var checkResults []CheckResult
	err := json.NewDecoder(logsReader).Decode(&checkResults)

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

	imageRef, err := p.config.GetConftestImageRef()
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	return v1alpha1.ConfigAuditResult{
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
