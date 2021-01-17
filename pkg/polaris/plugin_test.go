package polaris_test

import (
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/pointer"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

func TestPlugin_GetScanJobSpec(t *testing.T) {
	testCases := []struct {
		name string

		config   starboard.ConfigData
		workload kube.Object
		gvk      schema.GroupVersionKind

		expectedJobSpec corev1.PodSpec
	}{
		{
			name: "Should return job spec for Deployment",
			config: starboard.ConfigData{
				"polaris.imageRef": "quay.io/fairwinds/polaris:3.0",
			},
			workload: kube.Object{
				Name:      "nginx",
				Namespace: corev1.NamespaceDefault,
				Kind:      kube.KindDeployment,
			},
			gvk: schema.GroupVersionKind{
				Group:   "apps",
				Version: "v1",
				Kind:    "Deployment",
			},
			expectedJobSpec: corev1.PodSpec{
				ServiceAccountName:           starboard.ServiceAccountName,
				AutomountServiceAccountToken: pointer.BoolPtr(true),
				RestartPolicy:                corev1.RestartPolicyNever,
				Affinity:                     starboard.LinuxNodeAffinity(),
				Volumes: []corev1.Volume{
					{
						Name: "config",
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
						Name:                     "polaris",
						Image:                    "quay.io/fairwinds/polaris:3.0",
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
								Name:      "config",
								MountPath: "/etc/starboard",
							},
						},
						Command: []string{"polaris"},
						Args: []string{
							"audit",
							"--log-level", "error",
							"--config", "/etc/starboard/polaris.config.yaml",
							"--resource", "default/Deployment.apps/v1/nginx",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plugin := polaris.NewPlugin(fixedClock, tc.config)
			jobSpec, err := plugin.GetScanJobSpec(tc.workload, tc.gvk)
			require.NoError(t, err, tc.name)
			assert.Equal(t, tc.expectedJobSpec, jobSpec, tc.name)
		})
	}

}

func TestPlugin_GetContainerName(t *testing.T) {
	plugin := polaris.NewPlugin(fixedClock, starboard.ConfigData{})
	assert.Equal(t, "polaris", plugin.GetContainerName())
}

func TestPlugin_ParseConfigAuditResult(t *testing.T) {
	testReport, err := os.Open("testdata/polaris-report.json")
	require.NoError(t, err)
	defer func() {
		_ = testReport.Close()
	}()

	config := starboard.ConfigData{
		"polaris.imageRef": "quay.io/fairwinds/polaris:3.0",
	}
	plugin := polaris.NewPlugin(fixedClock, config)
	result, err := plugin.ParseConfigAuditResult(testReport)
	require.NoError(t, err)
	assert.Equal(t, metav1.NewTime(fixedTime), result.UpdateTimestamp)
	assert.Equal(t, v1alpha1.Scanner{
		Name:    "Polaris",
		Vendor:  "Fairwinds Ops",
		Version: "3.0",
	}, result.Scanner)
	assert.Equal(t, v1alpha1.ConfigAuditSummary{
		PassCount:    2,
		DangerCount:  1,
		WarningCount: 1,
	}, result.Summary)
	assert.ElementsMatch(t, []v1alpha1.Check{
		{
			ID:       "hostIPCSet",
			Message:  "Host IPC is not configured",
			Success:  false,
			Severity: "danger",
			Category: "Security",
		},
		{
			ID:       "hostNetworkSet",
			Message:  "Host network is not configured",
			Success:  true,
			Severity: "warning",
			Category: "Networking",
		},
	}, result.PodChecks)
	assert.Len(t, result.ContainerChecks, 1)
	assert.ElementsMatch(t, []v1alpha1.Check{
		{
			ID:       "cpuLimitsMissing",
			Message:  "CPU limits are set",
			Success:  false,
			Severity: "warning",
			Category: "Resources",
		},
		{
			ID:       "cpuRequestsMissing",
			Message:  "CPU requests are set",
			Success:  true,
			Severity: "warning",
			Category: "Resources",
		},
	}, result.ContainerChecks["db"])
}
