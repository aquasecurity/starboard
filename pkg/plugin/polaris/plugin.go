package polaris

import (
	"encoding/json"
	"fmt"
	"io"

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
)

const (
	polarisContainerName = "polaris"
	configVolume         = "config"
)

type Config interface {
	GetPolarisImageRef() (string, error)
}

type plugin struct {
	clock  ext.Clock
	config Config
}

// NewPlugin constructs a new configauditreport.Plugin, which is using an
// official Polaris container image to audit Kubernetes workloads.
func NewPlugin(clock ext.Clock, config Config) configauditreport.Plugin {
	return &plugin{
		clock:  clock,
		config: config,
	}
}

func (p *plugin) GetConfigHash(_ starboard.PluginContext) (string, error) {
	// TODO Compute config hash based on Polaris config
	return kube.ComputeHash("TODO"), nil
}

func (p *plugin) GetScanJobSpec(ctx starboard.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	imageRef, err := p.config.GetPolarisImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	sourceName := p.sourceNameFrom(obj)

	return corev1.PodSpec{
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(true),
		RestartPolicy:                corev1.RestartPolicyNever,
		Affinity:                     starboard.LinuxNodeAffinity(),
		Volumes: []corev1.Volume{
			{
				Name: configVolume,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
					},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:                     polarisContainerName,
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
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      configVolume,
						MountPath: "/etc/starboard",
					},
				},
				Command: []string{"polaris"},
				Args: []string{
					"audit",
					"--log-level", "error",
					"--config", "/etc/starboard/polaris.config.yaml",
					"--resource", sourceName,
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
	}, nil, nil
}

func (p *plugin) GetContainerName() string {
	return polarisContainerName
}

func (p *plugin) ParseConfigAuditReportData(logsReader io.ReadCloser) (v1alpha1.ConfigAuditResult, error) {
	var report Report
	err := json.NewDecoder(logsReader).Decode(&report)
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}
	return p.configAuditResultFrom(report.Results[0])
}

func (p *plugin) sourceNameFrom(obj client.Object) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	group := gvk.Group
	if len(group) > 0 {
		group = "." + group
	}
	return fmt.Sprintf("%s/%s%s/%s/%s",
		obj.GetNamespace(),
		gvk.Kind,
		group,
		gvk.Version,
		obj.GetName(),
	)
}

func (p *plugin) configAuditResultFrom(result Result) (v1alpha1.ConfigAuditResult, error) {
	var podChecks []v1alpha1.Check
	containerChecks := make(map[string][]v1alpha1.Check)

	for _, pr := range result.PodResult.Results {
		podChecks = append(podChecks, v1alpha1.Check{
			ID:       pr.ID,
			Message:  pr.Message,
			Success:  pr.Success,
			Severity: pr.Severity,
			Category: pr.Category,
		})
	}

	for _, cr := range result.PodResult.ContainerResults {
		var checks []v1alpha1.Check
		for _, crr := range cr.Results {
			checks = append(checks, v1alpha1.Check{
				ID:       crr.ID,
				Message:  crr.Message,
				Success:  crr.Success,
				Severity: crr.Severity,
				Category: crr.Category,
			})

		}
		containerChecks[cr.Name] = checks
	}

	imageRef, err := p.config.GetPolarisImageRef()
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	return v1alpha1.ConfigAuditResult{
		Scanner: v1alpha1.Scanner{
			Name:    "Polaris",
			Vendor:  "Fairwinds Ops",
			Version: version,
		},
		Summary:         p.configAuditSummaryFrom(podChecks, containerChecks),
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		PodChecks:       podChecks,
		ContainerChecks: containerChecks,
	}, nil
}

func (p *plugin) configAuditSummaryFrom(podChecks []v1alpha1.Check, containerChecks map[string][]v1alpha1.Check) v1alpha1.ConfigAuditSummary {
	var summary v1alpha1.ConfigAuditSummary
	for _, c := range podChecks {
		if c.Success {
			summary.PassCount++
			continue
		}
		switch c.Severity {
		case v1alpha1.ConfigAuditDangerSeverity:
			summary.DangerCount++
		case v1alpha1.ConfigAuditWarningSeverity:
			summary.WarningCount++
		}
	}
	for _, checks := range containerChecks {
		for _, c := range checks {
			if c.Success {
				summary.PassCount++
				continue
			}
			switch c.Severity {
			case v1alpha1.ConfigAuditDangerSeverity:
				summary.DangerCount++
			case v1alpha1.ConfigAuditWarningSeverity:
				summary.WarningCount++
			}
		}
	}
	return summary
}
