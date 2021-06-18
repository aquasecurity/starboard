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

const (
	polarisConfigYAML = `checks:
  # reliability
  multipleReplicasForDeployment: ignore
  priorityClassNotSet: ignore
  # resources
  cpuRequestsMissing: warning
  cpuLimitsMissing: warning
  memoryRequestsMissing: warning
  memoryLimitsMissing: warning
  # images
  tagNotSpecified: danger
  pullPolicyNotAlways: ignore
  # healthChecks
  readinessProbeMissing: warning
  livenessProbeMissing: warning
  # networking
  hostNetworkSet: warning
  hostPortSet: warning
  # security
  hostIPCSet: danger
  hostPIDSet: danger
  notReadOnlyRootFilesystem: warning
  privilegeEscalationAllowed: danger
  runAsRootAllowed: warning
  runAsPrivileged: danger
  dangerousCapabilities: danger
  insecureCapabilities: warning
exemptions:
  - controllerNames:
    - kube-apiserver
    - kube-proxy
    - kube-scheduler
    - etcd-manager-events
    - kube-controller-manager
    - kube-dns
    - etcd-manager-main
    rules:
    - hostPortSet
    - hostNetworkSet
    - readinessProbeMissing
    - livenessProbeMissing
    - cpuRequestsMissing
    - cpuLimitsMissing
    - memoryRequestsMissing
    - memoryLimitsMissing
    - runAsRootAllowed
    - runAsPrivileged
    - notReadOnlyRootFilesystem
    - hostPIDSet
  - controllerNames:
    - kube-flannel-ds
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - notReadOnlyRootFilesystem
    - readinessProbeMissing
    - livenessProbeMissing
    - cpuLimitsMissing
  - controllerNames:
    - cert-manager
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
  - controllerNames:
    - cluster-autoscaler
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - readinessProbeMissing
  - controllerNames:
    - vpa
    rules:
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
    - notReadOnlyRootFilesystem
  - controllerNames:
    - datadog
    rules:
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
    - notReadOnlyRootFilesystem
  - controllerNames:
    - nginx-ingress-controller
    rules:
    - privilegeEscalationAllowed
    - insecureCapabilities
    - runAsRootAllowed
  - controllerNames:
    - dns-controller
    - datadog-datadog
    - kube-flannel-ds
    - kube2iam
    - aws-iam-authenticator
    - datadog
    - kube2iam
    rules:
    - hostNetworkSet
  - controllerNames:
    - aws-iam-authenticator
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - dnsmasq
    - autoscaler
    - kubernetes-dashboard
    - install-cni
    - kube2iam
    rules:
    - readinessProbeMissing
    - livenessProbeMissing
  - controllerNames:
    - aws-iam-authenticator
    - nginx-ingress-default-backend
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - kubedns
    - dnsmasq
    - autoscaler
    - tiller
    - kube2iam
    rules:
    - runAsRootAllowed
  - controllerNames:
    - aws-iam-authenticator
    - nginx-ingress-controller
    - nginx-ingress-default-backend
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - kubedns
    - dnsmasq
    - autoscaler
    - tiller
    - kube2iam
    rules:
    - notReadOnlyRootFilesystem
  - controllerNames:
    - cert-manager
    - dns-controller
    - kubedns
    - dnsmasq
    - autoscaler
    - insights-agent-goldilocks-vpa-install
    - datadog
    rules:
    - cpuRequestsMissing
    - cpuLimitsMissing
    - memoryRequestsMissing
    - memoryLimitsMissing
  - controllerNames:
    - kube2iam
    - kube-flannel-ds
    rules:
    - runAsPrivileged
  - controllerNames:
    - kube-hunter
    rules:
    - hostPIDSet
  - controllerNames:
    - polaris
    - kube-hunter
    - goldilocks
    - insights-agent-goldilocks-vpa-install
    rules:
    - notReadOnlyRootFilesystem
  - controllerNames:
    - insights-agent-goldilocks-controller
    rules:
    - livenessProbeMissing
    - readinessProbeMissing
  - controllerNames:
    - insights-agent-goldilocks-vpa-install
    - kube-hunter
    rules:
    - runAsRootAllowed
`
)

type plugin struct {
	clock ext.Clock
}

// NewPlugin constructs a new configauditreport.Plugin, which is using an
// official Polaris container image to audit Kubernetes workloads.
func NewPlugin(clock ext.Clock) configauditreport.Plugin {
	return &plugin{
		clock: clock,
	}
}

func (p *plugin) Init(ctx starboard.PluginContext) error {
	return ctx.EnsureConfig(starboard.PluginConfig{
		Data: map[string]string{
			"polaris.imageRef":    "quay.io/fairwinds/polaris:3.2",
			"polaris.config.yaml": polarisConfigYAML,
		},
	})
}

func (p *plugin) GetConfigHash(ctx starboard.PluginContext) (string, error) {
	cm, err := ctx.GetConfig()
	if err != nil {
		return "", err
	}
	return kube.ComputeHash(cm.Data), nil
}

func (p *plugin) getImageRef(ctx starboard.PluginContext) (string, error) {
	config, err := ctx.GetConfig()
	if err != nil {
		return "", err
	}
	return config.GetRequiredData("polaris.imageRef")
}

func (p *plugin) GetScanJobSpec(ctx starboard.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	imageRef, err := p.getImageRef(ctx)
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
							Name: starboard.GetPluginConfigMapName(ctx.GetName()),
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
				Command: []string{"sh"},
				Args: []string{
					"-c",
					"polaris audit --log-level error --config /etc/starboard/polaris.config.yaml --resource " + sourceName + " 2> /dev/null",
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
	}, nil, nil
}

func (p *plugin) GetContainerName() string {
	return polarisContainerName
}

func (p *plugin) ParseConfigAuditReportData(ctx starboard.PluginContext, logsReader io.ReadCloser) (v1alpha1.ConfigAuditReportData, error) {
	var report Report
	err := json.NewDecoder(logsReader).Decode(&report)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, err
	}
	return p.configAuditReportDataFrom(ctx, report.Results[0])
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

func (p *plugin) configAuditReportDataFrom(ctx starboard.PluginContext, result Result) (v1alpha1.ConfigAuditReportData, error) {
	var checks []v1alpha1.Check
	var podChecks []v1alpha1.Check
	containerNameToChecks := make(map[string][]v1alpha1.Check)

	for _, pr := range result.PodResult.Results {
		check := v1alpha1.Check{
			ID:       pr.ID,
			Message:  pr.Message,
			Success:  pr.Success,
			Severity: pr.Severity,
			Category: pr.Category,
		}
		checks = append(checks, check)
		podChecks = append(podChecks, check)
	}

	for _, cr := range result.PodResult.ContainerResults {
		var containerChecks []v1alpha1.Check
		for _, crr := range cr.Results {
			containerChecks = append(containerChecks, v1alpha1.Check{
				ID:       crr.ID,
				Message:  crr.Message,
				Success:  crr.Success,
				Severity: crr.Severity,
				Category: crr.Category,
				Scope: &v1alpha1.CheckScope{
					Type:  "Container",
					Value: cr.Name,
				},
			})

		}
		checks = append(checks, containerChecks...)
		containerNameToChecks[cr.Name] = containerChecks
	}

	imageRef, err := p.getImageRef(ctx)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, err
	}

	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, err
	}

	return v1alpha1.ConfigAuditReportData{
		Scanner: v1alpha1.Scanner{
			Name:    "Polaris",
			Vendor:  "Fairwinds Ops",
			Version: version,
		},
		Summary:         p.configAuditSummaryFrom(podChecks, containerNameToChecks),
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Checks:          checks,
		// TODO Deprecate PodChecks and ContainerChecks in 0.12+
		PodChecks:       podChecks,
		ContainerChecks: containerNameToChecks,
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
		case v1alpha1.ConfigAuditSeverityDanger:
			summary.DangerCount++
		case v1alpha1.ConfigAuditSeverityWarning:
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
			case v1alpha1.ConfigAuditSeverityDanger:
				summary.DangerCount++
			case v1alpha1.ConfigAuditSeverityWarning:
				summary.WarningCount++
			}
		}
	}
	return summary
}
