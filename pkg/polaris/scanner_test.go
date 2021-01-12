package polaris_test

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/pointer"
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
			plugin := polaris.NewPlugin(tc.config)
			jobSpec, err := plugin.GetScanJobSpec(tc.workload, tc.gvk)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}

}
