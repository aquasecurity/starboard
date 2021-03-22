package trivy_test

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/plugin/trivy"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/pointer"
)

func TestScanner_GetScanJobSpec(t *testing.T) {

	testCases := []struct {
		name string

		config       starboard.ConfigData
		workloadSpec corev1.PodSpec

		expectedSecrets []corev1.Secret
		expectedJobSpec corev1.PodSpec
	}{
		{
			name: "With Standalone mode",
			config: starboard.ConfigData{
				"trivy.imageRef": "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":     string(starboard.Standalone),
			},
			workloadSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.16",
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					{
						Name: "data",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
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
							"--cache-dir", "/var/lib/trivy",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "data",
								MountPath: "/var/lib/trivy",
								ReadOnly:  false,
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{{
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
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--skip-update",
							"--cache-dir", "/var/lib/trivy",
							"--quiet",
							"--format", "json",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "data",
								ReadOnly:  false,
								MountPath: "/var/lib/trivy",
							},
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
			},
		},
		{
			name: "With ClientServer mode",
			config: starboard.ConfigData{
				"trivy.imageRef":  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":      string(starboard.ClientServer),
				"trivy.serverURL": "http://trivy.trivy:4954",
			},
			workloadSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.16",
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				RestartPolicy:                corev1.RestartPolicyNever,
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
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
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"client",
							"--quiet",
							"--format",
							"json",
							"--remote",
							"http://trivy.trivy:4954",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jobSpec, secrets, err := trivy.NewPlugin(ext.NewSimpleIDGenerator(), tc.config).
				GetScanJobSpec(tc.workloadSpec, nil)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}

}
