package polaris_test

import (
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/plugin/polaris"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

func TestPlugin_GetScanJobSpec(t *testing.T) {
	testCases := []struct {
		name string

		config starboard.ConfigData
		obj    client.Object

		expectedJobSpec corev1.PodSpec
	}{
		{
			name: "Should return job spec for Deployment",
			config: starboard.ConfigData{
				"polaris.imageRef": "quay.io/fairwinds/polaris:3.2",
			},
			obj: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: metav1.NamespaceDefault,
				},
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
									Name: starboard.GetPluginConfigMapName(string(starboard.Polaris)),
								},
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "polaris",
						Image:                    "quay.io/fairwinds/polaris:3.2",
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
						Command: []string{"sh"},
						Args: []string{
							"-c",
							"polaris audit --log-level error --config /etc/starboard/polaris.config.yaml --resource default/Deployment.apps/v1/nginx 2> /dev/null",
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
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewGomegaWithT(t)

			pluginContext := starboard.NewPluginContext().
				WithName(string(starboard.Polaris)).
				WithNamespace(starboard.NamespaceName).
				WithServiceAccountName(starboard.ServiceAccountName).
				Get()
			plugin := polaris.NewPlugin(fixedClock, tc.config)
			jobSpec, secrets, err := plugin.GetScanJobSpec(pluginContext, tc.obj)

			g.Expect(err).ToNot(gomega.HaveOccurred())
			g.Expect(secrets).To(gomega.BeNil())
			g.Expect(jobSpec).To(gomega.Equal(tc.expectedJobSpec))
		})
	}

}

func TestPlugin_GetContainerName(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	plugin := polaris.NewPlugin(fixedClock, starboard.ConfigData{})
	g.Expect(plugin.GetContainerName()).To(gomega.Equal("polaris"))
}

func TestPlugin_ParseConfigAuditReportData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	testReport, err := os.Open("testdata/polaris-report.json")
	g.Expect(err).ToNot(gomega.HaveOccurred())
	defer func() {
		_ = testReport.Close()
	}()

	config := starboard.ConfigData{
		"polaris.imageRef": "quay.io/fairwinds/polaris:3.2",
	}
	plugin := polaris.NewPlugin(fixedClock, config)
	result, err := plugin.ParseConfigAuditReportData(testReport)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(result.UpdateTimestamp).To(gomega.Equal(metav1.NewTime(fixedTime)))
	g.Expect(result.Scanner).To(gomega.Equal(v1alpha1.Scanner{
		Name:    "Polaris",
		Vendor:  "Fairwinds Ops",
		Version: "3.2",
	}))
	g.Expect(result.Summary).To(gomega.Equal(v1alpha1.ConfigAuditSummary{
		PassCount:    2,
		DangerCount:  1,
		WarningCount: 1,
	}))
	g.Expect(result.PodChecks).To(gomega.ConsistOf(v1alpha1.Check{
		ID:       "hostIPCSet",
		Message:  "Host IPC is not configured",
		Success:  false,
		Severity: "danger",
		Category: "Security",
	}, v1alpha1.Check{
		ID:       "hostNetworkSet",
		Message:  "Host network is not configured",
		Success:  true,
		Severity: "warning",
		Category: "Networking",
	}))
	g.Expect(result.ContainerChecks).To(gomega.HaveLen(1))
	g.Expect(result.ContainerChecks["db"]).To(gomega.ConsistOf(v1alpha1.Check{
		ID:       "cpuLimitsMissing",
		Message:  "CPU limits are set",
		Success:  false,
		Severity: "warning",
		Category: "Resources",
	}, v1alpha1.Check{
		ID:       "cpuRequestsMissing",
		Message:  "CPU requests are set",
		Success:  true,
		Severity: "warning",
		Category: "Resources",
	}))
}

func TestPlugin_GetConfigHash(t *testing.T) {

	newPluginContextWithConfigData := func(data map[string]string) starboard.PluginContext {
		return starboard.NewPluginContext().
			WithName(string(starboard.Polaris)).
			WithNamespace("starboard-ns").
			WithClient(fake.NewClientBuilder().
				WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "starboard-polaris-config",
						Namespace: "starboard-ns",
					},
					Data: data,
				}).
				Build()).
			Get()
	}

	t.Run("Should return different hash for different config data", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":   "bar",
			"brown": "fox",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"brown": "fox",
			"foo":   "baz",
		})

		plugin := polaris.NewPlugin(fixedClock, starboard.ConfigData{})
		hash1, err := plugin.GetConfigHash(pluginContext1)
		g.Expect(err).ToNot(gomega.HaveOccurred())

		hash2, err := plugin.GetConfigHash(pluginContext2)
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(hash1).ToNot(gomega.Equal(hash2))
	})

	t.Run("Should return the same hash for the same config data", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":   "bar",
			"brown": "fox",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"brown": "fox",
			"foo":   "bar",
		})

		plugin := polaris.NewPlugin(fixedClock, starboard.ConfigData{})
		hash1, err := plugin.GetConfigHash(pluginContext1)
		g.Expect(err).ToNot(gomega.HaveOccurred())

		hash2, err := plugin.GetConfigHash(pluginContext2)
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(hash1).To(gomega.Equal(hash2))
	})
}
