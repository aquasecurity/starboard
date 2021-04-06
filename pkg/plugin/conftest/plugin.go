package conftest

import (
	"encoding/json"
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
)

type Config interface {
	GetConftestImageRef() (string, error)
}

type plugin struct {
	idGenerator ext.IDGenerator
	clock       ext.Clock
	config      Config
}

// NewPlugin constructs a new configauditreport.Plugin, which is using an
// official Conftest container image to audit Kubernetes workloads.
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
		return corev1.PodSpec{}, nil, err
	}

	var secrets []*corev1.Secret

	workloadAsYAML, err := yaml.Marshal(obj)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.idGenerator.GenerateID(),
		},
		StringData: map[string]string{
			"workload.yaml": string(workloadAsYAML),
		},
	}

	secrets = append(secrets, secret)

	policies, err := p.getPolicies(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	var volumeMounts []corev1.VolumeMount
	var volumeItems []corev1.KeyToPath

	for _, control := range policies {

		volumeItems = append(volumeItems, corev1.KeyToPath{
			Key:  "conftest.policy." + control,
			Path: control + ".rego",
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "policies",
			MountPath: "/project/policy/" + control + ".rego",
			SubPath:   control + ".rego",
		})

	}

	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      secret.Name,
		MountPath: "/project/workload.yaml",
		SubPath:   "workload.yaml",
	})

	return corev1.PodSpec{
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		RestartPolicy:                corev1.RestartPolicyNever,
		Affinity:                     starboard.LinuxNodeAffinity(),
		Volumes: []corev1.Volume{
			{
				Name: "policies",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "conftestconfig",
						},
						Items: volumeItems,
					},
				},
			},
			{
				Name: secret.Name,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secret.Name,
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
		SecurityContext: &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(1000),
			RunAsGroup: pointer.Int64Ptr(1000),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
	}, secrets, nil

}

func (p *plugin) getPolicies(ctx starboard.PluginContext) ([]string, error) {
	cm, err := ctx.GetConfig()
	if err != nil {
		return nil, err
	}

	var policies []string

	for key := range cm.Data {
		if !strings.HasPrefix(key, "conftest.policy.") {
			continue
		}
		policyName := strings.TrimPrefix(key, "conftest.policy.")
		policies = append(policies, policyName)
	}

	return policies, nil
}

func (p *plugin) GetContainerName() string {
	return conftestContainerName
}

const (
	defaultCategory = "Security"
)

func (p *plugin) ParseConfigAuditReportData(logsReader io.ReadCloser) (v1alpha1.ConfigAuditResult, error) {
	var checkResults []CheckResult
	err := json.NewDecoder(logsReader).Decode(&checkResults)

	checks := make([]v1alpha1.Check, 0)
	var successesCount, warningCount, dangerCount int

	for _, cr := range checkResults {
		successesCount += cr.Successes

		for _, warning := range cr.Warnings {
			checks = append(checks, v1alpha1.Check{
				ID:       p.getPolicyTitleFromResult(warning),
				Severity: "WARNING",
				Message:  warning.Message,
				Category: defaultCategory,
				Success:  false,
			})
			warningCount++
		}

		for _, failure := range cr.Failures {
			checks = append(checks, v1alpha1.Check{
				ID:       p.getPolicyTitleFromResult(failure),
				Severity: "DANGER",
				Message:  failure.Message,
				Category: defaultCategory,
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
			PassCount:    successesCount, // TODO This should be a pointer to tell 0 from nil
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
