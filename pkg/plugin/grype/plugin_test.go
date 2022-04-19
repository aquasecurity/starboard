package grype_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/plugin/grype"
	"github.com/aquasecurity/starboard/pkg/plugin/trivy"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

const defaultUpdateURL = "https://toolbox-data.anchore.io/grype/databases/listing.json"

func TestConfig_GetImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       trivy.Config
		expectedError    string
		expectedImageRef string
	}{
		{
			name:          "Should return error",
			configData:    trivy.Config{PluginConfig: starboard.PluginConfig{}},
			expectedError: "property trivy.imageRef not set",
		},
		{
			name: "Should return image reference from config data",
			configData: trivy.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"trivy.imageRef": "gcr.io/aquasecurity/trivy:0.8.0",
				},
			}},
			expectedImageRef: "gcr.io/aquasecurity/trivy:0.8.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageRef, err := tc.configData.GetImageRef()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedImageRef, imageRef)
			}
		})
	}
}

func TestConfig_GetResourceRequirements(t *testing.T) {
	testCases := []struct {
		name                 string
		config               trivy.Config
		expectedError        string
		expectedRequirements corev1.ResourceRequirements
	}{
		{
			name: "Should return empty requirements by default",
			config: trivy.Config{
				PluginConfig: starboard.PluginConfig{},
			},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{},
				Limits:   corev1.ResourceList{},
			},
		},
		{
			name: "Should return configured resource requirement",
			config: trivy.Config{
				PluginConfig: starboard.PluginConfig{
					Data: map[string]string{
						"trivy.dbRepository":              defaultUpdateURL,
						"trivy.resources.requests.cpu":    "800m",
						"trivy.resources.requests.memory": "200M",
						"trivy.resources.limits.cpu":      "600m",
						"trivy.resources.limits.memory":   "700M",
					},
				},
			},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("800m"),
					corev1.ResourceMemory: resource.MustParse("200M"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("600m"),
					corev1.ResourceMemory: resource.MustParse("700M"),
				},
			},
		},
		{
			name: "Should return error if resource is not parseable",
			config: trivy.Config{
				PluginConfig: starboard.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.cpu": "roughly 100",
					},
				},
			},
			expectedError: "parsing resource definition trivy.resources.requests.cpu: roughly 100 quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resourceRequirement, err := tc.config.GetResourceRequirements()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedRequirements, resourceRequirement, tc.name)
			}
		})
	}
}

func TestConfig_IgnoreUnfixed(t *testing.T) {
	testCases := []struct {
		name           string
		configData     trivy.Config
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: trivy.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: trivy.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo":                 "bar",
					"trivy.ignoreUnfixed": "true",
				},
			}},
			expectedOutput: true,
		},
		{
			name: "Should return false when set it as false",
			configData: trivy.Config{PluginConfig: starboard.PluginConfig{
				Data: map[string]string{
					"foo":                 "bar",
					"trivy.ignoreUnfixed": "false",
				},
			}},
			expectedOutput: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exists := tc.configData.IgnoreUnfixed()
			assert.Equal(t, tc.expectedOutput, exists)
		})
	}
}

func TestPlugin_Init(t *testing.T) {

	t.Run("Should create the default config", func(t *testing.T) {
		client := fake.NewClientBuilder().WithObjects().Build()

		instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), client)

		pluginContext := starboard.NewPluginContext().
			WithName(trivy.Plugin).
			WithNamespace("starboard-ns").
			WithServiceAccountName("starboard-sa").
			WithClient(client).
			Get()
		err := instance.Init(pluginContext)
		require.NoError(t, err)

		var cm corev1.ConfigMap
		err = client.Get(context.Background(), types.NamespacedName{
			Namespace: "starboard-ns",
			Name:      "starboard-trivy-config",
		}, &cm)
		require.NoError(t, err)
		assert.Equal(t, corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "starboard-trivy-config",
				Namespace: "starboard-ns",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "starboard",
				},
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"trivy.imageRef":     "docker.io/aquasec/trivy:0.25.2",
				"trivy.severity":     "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				"trivy.mode":         "Standalone",
				"trivy.timeout":      "5m0s",
				"trivy.dbRepository": defaultUpdateURL,

				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
		}, cm)
	})

	t.Run("Should not overwrite existing config", func(t *testing.T) {
		client := fake.NewClientBuilder().WithObjects(
			&corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "starboard-trivy-config",
					Namespace:       "starboard-ns",
					ResourceVersion: "1",
				},
				Data: map[string]string{
					"trivy.imageRef": "docker.io/aquasec/trivy:0.25.2",
					"trivy.severity": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					"trivy.mode":     "Standalone",
				},
			}).Build()

		instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), client)

		pluginContext := starboard.NewPluginContext().
			WithName(trivy.Plugin).
			WithNamespace("starboard-ns").
			WithServiceAccountName("starboard-sa").
			WithClient(client).
			Get()
		err := instance.Init(pluginContext)
		require.NoError(t, err)

		var cm corev1.ConfigMap
		err = client.Get(context.Background(), types.NamespacedName{
			Namespace: "starboard-ns",
			Name:      "starboard-trivy-config",
		}, &cm)
		require.NoError(t, err)
		assert.Equal(t, corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "starboard-trivy-config",
				Namespace:       "starboard-ns",
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"trivy.imageRef": "docker.io/aquasec/trivy:0.25.2",
				"trivy.severity": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				"trivy.mode":     "Standalone",
			},
		}, cm)
	})
}

const (
	grypeDBLocation        = "/tmp/grypedb"
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

func TestPlugin_GetScanJobSpec(t *testing.T) {

	commonEnv := []corev1.EnvVar{
		{
			Name: "HTTP_PROXY",
			ValueFrom: &corev1.EnvVarSource{
				ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: grype.Plugin,
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
						Name: grype.Plugin,
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
						Name: grype.Plugin,
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
						Name: grype.Plugin,
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

	tmpVolume := corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}

	tmpVolumeMount := corev1.VolumeMount{
		Name:      "tmp",
		MountPath: grypeDBLocation,
		ReadOnly:  false,
	}

	testCases := []struct {
		name string

		config       map[string]string
		workloadSpec client.Object

		expectedSecrets []corev1.Secret
		expectedJobSpec corev1.PodSpec
	}{
		{
			name: "grype",
			config: map[string]string{
				"grype.imageRef":                  "anchore/grype:v0.34.7",
				"grype.updateURL":                 defaultUpdateURL,
				"grype.resources.requests.cpu":    "100m",
				"grype.resources.requests.memory": "100M",
				"grype.resources.limits.cpu":      "500m",
				"grype.resources.limits.memory":   "500M",
			},
			workloadSpec: &appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-6799fc88d8",
					Namespace: "prod-ns",
				},
				Spec: appsv1.ReplicaSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "anchore/grype:v0.34.7",
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
							tmpVolumeMount,
						},
					},
				},
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
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
							tmpVolumeMount,
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
		{
			name: "Standalone mode with insecure registry",
			config: map[string]string{
				"trivy.imageRef":                     "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                         string(trivy.Standalone),
				"trivy.insecureRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"trivy.dbRepository":                 defaultUpdateURL,

				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultUpdateURL,
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
							tmpVolumeMount,
						},
					},
				},
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
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
							tmpVolumeMount,
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
		{
			name: "Standalone mode with non-SSL registry",
			config: map[string]string{
				"trivy.imageRef":                   "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                       string(trivy.Standalone),
				"trivy.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"trivy.dbRepository":               defaultUpdateURL,
				"trivy.resources.requests.cpu":     "100m",
				"trivy.resources.requests.memory":  "100M",
				"trivy.resources.limits.cpu":       "500m",
				"trivy.resources.limits.memory":    "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultUpdateURL,
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
							tmpVolumeMount,
						},
					},
				},
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
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
							tmpVolumeMount,
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
		{
			name: "Standalone mode with trivyignore file",
			config: map[string]string{
				"trivy.imageRef": "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":     string(trivy.Standalone),
				"trivy.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				"trivy.dbRepository":              defaultUpdateURL,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "starboard-trivy-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "trivy.ignoreFile",
										Path: ".trivyignore",
									},
								},
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultUpdateURL,
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
							tmpVolumeMount,
						},
					},
				},
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_IGNOREFILE",
								Value: "/etc/trivy/.trivyignore",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
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
							tmpVolumeMount,
							{
								Name:      "ignorefile",
								MountPath: "/etc/trivy/.trivyignore",
								SubPath:   ".trivyignore",
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
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with mirror",
			config: map[string]string{
				"trivy.imageRef": "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":     string(trivy.Standalone),

				"trivy.dbRepository":              defaultUpdateURL,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",

				"trivy.registry.mirror.index.docker.io": "mirror.io",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultUpdateURL,
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
							tmpVolumeMount,
						},
					},
				},
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"mirror.io/library/nginx:1.16",
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
							tmpVolumeMount,
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
		{
			name: "ClientServer mode without insecure registry",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                      string(trivy.ClientServer),
				"trivy.serverURL":                 "http://trivy.trivy:4954",
				"trivy.dbRepository":              defaultUpdateURL,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--quiet",
							"client",
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
		{
			name: "ClientServer mode without insecure registry",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                      string(trivy.ClientServer),
				"trivy.serverURL":                 "http://trivy.trivy:4954",
				"trivy.dbRepository":              defaultUpdateURL,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--quiet",
							"client",
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
		{
			name: "ClientServer mode with insecure server",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                      string(trivy.ClientServer),
				"trivy.serverURL":                 "https://trivy.trivy:4954",
				"trivy.serverInsecure":            "true",
				"trivy.dbRepository":              defaultUpdateURL,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"https://trivy.trivy:4954",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
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
		{
			name: "ClientServer mode with non-SSL registry",
			config: map[string]string{
				"trivy.imageRef":                   "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                       string(trivy.ClientServer),
				"trivy.serverURL":                  "http://trivy.trivy:4954",
				"trivy.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"trivy.dbRepository":               defaultUpdateURL,
				"trivy.resources.requests.cpu":     "100m",
				"trivy.resources.requests.memory":  "100M",
				"trivy.resources.limits.cpu":       "500m",
				"trivy.resources.limits.memory":    "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://trivy.trivy:4954",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
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
		{
			name: "ClientServer mode with trivyignore file",
			config: map[string]string{
				"trivy.imageRef":  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":      string(trivy.ClientServer),
				"trivy.serverURL": "http://trivy.trivy:4954",
				"trivy.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				"trivy.dbRepository":              defaultUpdateURL,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "starboard-trivy-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "trivy.ignoreFile",
										Path: ".trivyignore",
									},
								},
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
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_IGNOREFILE",
								Value: "/etc/trivy/.trivyignore",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--quiet",
							"client",
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
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "ignorefile",
								MountPath: "/etc/trivy/.trivyignore",
								SubPath:   ".trivyignore",
							},
						},
					},
				},
			},
		},
		{
			name: "Trivy fs scan command in Standalone mode",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.25.2",
				"trivy.mode":                      string(trivy.Standalone),
				"trivy.command":                   string(trivy.Filesystem),
				"trivy.dbRepository":              defaultUpdateURL,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.9.1",
						},
					},
					NodeName: "kind-control-pane",
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     starboard.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "starboard-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					{
						Name: trivy.FsSharedVolumeName,
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
						Image:                    "docker.io/aquasec/trivy:0.25.2",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Command: []string{
							"cp",
							"-v",
							"/usr/local/bin/trivy",
							trivy.SharedVolumeLocationOfTrivy,
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
								Name:      trivy.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/starboard",
							},
						},
					},
					{
						Name:                     "00000000-0000-0000-0000-000000000002",
						Image:                    "docker.io/aquasec/trivy:0.25.2",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
							"--cache-dir",
							"/var/starboard/trivy-db",
							"--db-repository", defaultUpdateURL,
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
								Name:      trivy.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/starboard",
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "nginx:1.9.1",
						ImagePullPolicy:          corev1.PullNever,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
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
											Name: "starboard-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							trivy.SharedVolumeLocationOfTrivy,
						},
						Args: []string{
							"--skip-update",
							"--cache-dir",
							"/var/starboard/trivy-db",
							"--quiet",
							"fs",
							"--format",
							"json",
							"/",
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
								Name:      trivy.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/starboard",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
							RunAsUser:              pointer.Int64(0),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
				NodeName:        "kind-control-pane",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "starboard-trivy-config",
						Namespace: "starboard-ns",
					},
					Data: tc.config,
				},
			).Build()
			pluginContext := starboard.NewPluginContext().
				WithName(grype.Plugin).
				WithNamespace("starboard-ns").
				WithServiceAccountName("starboard-sa").
				WithClient(fakeclient).
				Get()
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), fakeclient)
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, nil)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}

	testCases = []struct {
		name            string
		config          map[string]string
		workloadSpec    client.Object
		expectedSecrets []corev1.Secret
		expectedJobSpec corev1.PodSpec
	}{{
		name: "Trivy fs scan command in Standalone mode",
		config: map[string]string{
			"trivy.imageRef":                  "docker.io/aquasec/trivy:0.22.0",
			"trivy.mode":                      string(trivy.Standalone),
			"trivy.command":                   string(trivy.Filesystem),
			"trivy.dbRepository":              defaultUpdateURL,
			"trivy.resources.requests.cpu":    "100m",
			"trivy.resources.requests.memory": "100M",
			"trivy.resources.limits.cpu":      "500m",
			"trivy.resources.limits.memory":   "500M",
		},
		workloadSpec: &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: "prod-ns",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.9.1",
					},
				},
				NodeName:           "kind-control-pane",
				ServiceAccountName: "nginx-sa",
			}},
		expectedJobSpec: corev1.PodSpec{
			Affinity:                     starboard.LinuxNodeAffinity(),
			RestartPolicy:                corev1.RestartPolicyNever,
			ServiceAccountName:           "starboard-sa",
			AutomountServiceAccountToken: pointer.BoolPtr(false),
			Volumes: []corev1.Volume{
				{
					Name: trivy.FsSharedVolumeName,
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
					Image:                    "docker.io/aquasec/trivy:0.22.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Command: []string{
						"cp",
						"-v",
						"/usr/local/bin/trivy",
						trivy.SharedVolumeLocationOfTrivy,
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
							Name:      trivy.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/starboard",
						},
					},
				},
				{
					Name:                     "00000000-0000-0000-0000-000000000002",
					Image:                    "docker.io/aquasec/trivy:0.22.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-trivy-config",
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
										Name: "starboard-trivy-config",
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
										Name: "starboard-trivy-config",
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
										Name: "starboard-trivy-config",
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
						"--cache-dir",
						"/var/starboard/trivy-db",
						"--db-repository", defaultUpdateURL,
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
							Name:      trivy.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/starboard",
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:                     "nginx",
					Image:                    "nginx:1.9.1",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "TRIVY_SEVERITY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-trivy-config",
									},
									Key:      "trivy.severity",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "TRIVY_SKIP_FILES",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-trivy-config",
									},
									Key:      "trivy.skipFiles",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "TRIVY_SKIP_DIRS",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-trivy-config",
									},
									Key:      "trivy.skipDirs",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "starboard-trivy-config",
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
										Name: "starboard-trivy-config",
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
										Name: "starboard-trivy-config",
									},
									Key:      "trivy.noProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
					},
					Command: []string{
						trivy.SharedVolumeLocationOfTrivy,
					},
					Args: []string{
						"--skip-update",
						"--cache-dir",
						"/var/starboard/trivy-db",
						"--quiet",
						"fs",
						"--format",
						"json",
						"/",
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
							Name:      trivy.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/starboard",
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               pointer.BoolPtr(false),
						AllowPrivilegeEscalation: pointer.BoolPtr(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						RunAsUser:              pointer.Int64(0),
					},
				},
			},
			SecurityContext: &corev1.PodSecurityContext{},
		},
	}}
	// Test cases when starboard is enabled with option to run job in the namespace of workload
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "starboard-trivy-config",
						Namespace: "starboard-ns",
					},
					Data: tc.config,
				},
			).Build()
			pluginContext := starboard.NewPluginContext().
				WithName(trivy.Plugin).
				WithNamespace("starboard-ns").
				WithServiceAccountName("starboard-sa").
				WithClient(fakeclient).
				WithStarboardConfig(map[string]string{starboard.KeyVulnerabilityScansInSameNamespace: "true"}).
				Get()
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), fakeclient)
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, nil)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}
}

var (
	sampleReportAsString = `{
		"matches": [
		 {
		  "vulnerability": {
		   "id": "CVE-2015-5237",
		   "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2015-5237",
		   "namespace": "nvd",
		   "severity": "High",
		   "urls": [
			"https://github.com/google/protobuf/issues/760",
			"https://bugzilla.redhat.com/show_bug.cgi?id=1256426",
			"http://www.openwall.com/lists/oss-security/2015/08/27/2",
			"https://lists.apache.org/thread.html/b0656d359c7d40ec9f39c8cc61bca66802ef9a2a12ee199f5b0c1442@%3Cdev.drill.apache.org%3E",
			"https://lists.apache.org/thread.html/519eb0fd45642dcecd9ff74cb3e71c20a4753f7d82e2f07864b5108f@%3Cdev.drill.apache.org%3E",
			"https://lists.apache.org/thread.html/ra28fed69eef3a71e5fe5daea001d0456b05b102044237330ec5c7c82@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/f9bc3e55f4e28d1dcd1a69aae6d53e609a758e34d2869b4d798e13cc@%3Cissues.drill.apache.org%3E",
			"https://lists.apache.org/thread.html/r17dc6f394429f6bffb5e4c66555d93c2e9923cbbdc5a93db9a56c1c7@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/r42e47994734cd1980ef3e204a40555336e10cc80096927aca2f37d90@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/re6d04a214424a97ea59c62190d79316edf311a0a6346524dfef3b940@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/r1263fa5b51e4ec3cb8f09ff40e4747428c71198e9bee93349ec96a3c@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/r42ef6acfb0d86a2df0c2390702ecbe97d2104a331560f2790d17ca69@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/rb71dac1d9dd4e8a8ae3dbc033aeae514eda9be1263c1df3b42a530a2@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/r320dc858da88846ba00bb077bcca2cdf75b7dde0f6eb3a3d60dba6a1@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/r85c9a764b573c786224688cc906c27e28343e18f5b33387f94cae90f@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/r02e39d7beb32eebcdbb4b516e95f67d71c90d5d462b26f4078d21eeb@%3Cuser.flink.apache.org%3E",
			"https://lists.apache.org/thread.html/r02e39d7beb32eebcdbb4b516e95f67d71c90d5d462b26f4078d21eeb@%3Cdev.flink.apache.org%3E",
			"https://lists.apache.org/thread.html/r5e52caf41dc49df55b4ee80758356fe1ff2a88179ff24c685de7c28d@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/rf7539287c90be979bac94af9aaba34118fbf968864944b4871af48dd@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/r1d274d647b3c2060df9be21eade4ce56d3a59998cf19ac72662dd994@%3Ccommits.pulsar.apache.org%3E",
			"https://lists.apache.org/thread.html/r4886108206d4c535db9b20c813fe4723d4fe6a91b9278382af8b9d08@%3Cissues.spark.apache.org%3E",
			"https://lists.apache.org/thread.html/rb40dc9d63a5331bce8e80865b7fa3af9dd31e16555affd697b6f3526@%3Cissues.spark.apache.org%3E",
			"https://lists.apache.org/thread.html/r5741f4dbdd129dbb9885f5fb170dc1b24a06b9313bedef5e67fded94@%3Cissues.spark.apache.org%3E",
			"https://lists.apache.org/thread.html/r14fa8d38d5757254f1a2e112270c996711d514de2e3b01c93d397ab4@%3Cissues.spark.apache.org%3E",
			"https://lists.apache.org/thread.html/r2ea33ce5591a9cb9ed52750b6ab42ab658f529a7028c3166ba93c7d5@%3Ccommon-issues.hadoop.apache.org%3E",
			"https://lists.apache.org/thread.html/r00d9ab1fc0f1daf14cd4386564dd84f7889404438d81462c86dfa836@%3Ccommon-dev.hadoop.apache.org%3E",
			"https://lists.apache.org/thread.html/r764fc66435ee4d185d359c28c0887d3e5866d7292a8d5598d9e7cbc4@%3Ccommon-issues.hadoop.apache.org%3E",
			"https://lists.apache.org/thread.html/r0ca83171c4898dc92b86fa6f484a7be1dc96206765f4d01dce0f1b28@%3Ccommon-issues.hadoop.apache.org%3E",
			"https://lists.apache.org/thread.html/r00097d0b5b6164ea428554007121d5dc1f88ba2af7b9e977a10572cd@%3Cdev.hbase.apache.org%3E",
			"https://lists.apache.org/thread.html/rd64381fb8f92d640c1975dc50dcdf1b8512e02a2a7b20292d3565cae@%3Cissues.hbase.apache.org%3E",
			"https://lists.apache.org/thread.html/r4ef574a5621b0e670a3ce641e9922543e34f22bf4c9ee9584aa67fcf@%3Cissues.hbase.apache.org%3E",
			"https://lists.apache.org/thread.html/r7fed8dd9bee494094e7011cf3c2ab75bd8754ea314c6734688c42932@%3Ccommon-issues.hadoop.apache.org%3E"
		   ],
		   "description": "protobuf allows remote authenticated attackers to cause a heap-based buffer overflow.",
		   "cvss": [
			{
			 "version": "2.0",
			 "vector": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
			 "metrics": {
			  "baseScore": 6.5,
			  "exploitabilityScore": 8,
			  "impactScore": 6.4
			 },
			 "vendorMetadata": {}
			},
			{
			 "version": "3.1",
			 "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			 "metrics": {
			  "baseScore": 8.8,
			  "exploitabilityScore": 2.8,
			  "impactScore": 5.9
			 },
			 "vendorMetadata": {}
			}
		   ],
		   "fix": {
			"versions": [],
			"state": "unknown"
		   },
		   "advisories": []
		  },
		  "relatedVulnerabilities": [],
		  "matchDetails": [
		   {
			"type": "cpe-match",
			"matcher": "stock-matcher",
			"searchedBy": {
			 "namespace": "nvd",
			 "cpes": [
			  "cpe:2.3:a:google:protobuf:v1.27.1:*:*:*:*:*:*:*"
			 ]
			},
			"found": {
			 "versionConstraint": "<= 3.1.0 (unknown)",
			 "cpes": [
			  "cpe:2.3:a:google:protobuf:*:*:*:*:*:*:*:*"
			 ]
			}
		   }
		  ],
		  "artifact": {
		   "name": "google.golang.org/protobuf",
		   "version": "v1.27.1",
		   "type": "go-module",
		   "locations": [
			{
			 "path": "/grype",
			 "layerID": "sha256:65ea08da2c3941d8571059e12f7c48821150a89ba662c9751acf5d3664df3f86"
			}
		   ],
		   "language": "go",
		   "licenses": [],
		   "cpes": [
			"cpe:2.3:a:google:protobuf:v1.27.1:*:*:*:*:*:*:*"
		   ],
		   "purl": "pkg:golang/google.golang.org/protobuf@v1.27.1",
		   "upstreams": []
		  }
		 },
		 {
		  "vulnerability": {
		   "id": "CVE-2021-22570",
		   "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2021-22570",
		   "namespace": "nvd",
		   "severity": "High",
		   "urls": [
			"https://github.com/protocolbuffers/protobuf/releases/tag/v3.15.0",
			"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IFX6KPNOFHYD6L4XES5PCM3QNSKZBOTQ/",
			"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3DVUZPALAQ34TQP6KFNLM4IZS6B32XSA/",
			"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BTRGBRC5KGCA4SK5MUNLPYJRAGXMBIYY/",
			"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NVTWVQRB5OCCTMKEQFY5MYED3DXDVSLP/",
			"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5PAGL5M2KGYPN3VEQCRJJE6NA7D5YG5X/",
			"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KQJB6ZPRLKV6WCMX2PRRRQBFAOXFBK6B/",
			"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MRWRAXAFR3JR7XCFWTHC2KALSZKWACCE/"
		   ],
		   "description": "Nullptr dereference when a null char is present in a proto symbol. The symbol is parsed incorrectly, leading to an unchecked call into the proto file's name during generation of the resulting error message. Since the symbol is incorrectly parsed, the file is nullptr. We recommend upgrading to version 3.15.0 or greater.",
		   "cvss": [
			{
			 "version": "2.0",
			 "vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
			 "metrics": {
			  "baseScore": 5,
			  "exploitabilityScore": 10,
			  "impactScore": 2.9
			 },
			 "vendorMetadata": {}
			},
			{
			 "version": "3.1",
			 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			 "metrics": {
			  "baseScore": 7.5,
			  "exploitabilityScore": 3.9,
			  "impactScore": 3.6
			 },
			 "vendorMetadata": {}
			}
		   ],
		   "fix": {
			"versions": [],
			"state": "unknown"
		   },
		   "advisories": []
		  },
		  "relatedVulnerabilities": [],
		  "matchDetails": [
		   {
			"type": "cpe-match",
			"matcher": "stock-matcher",
			"searchedBy": {
			 "namespace": "nvd",
			 "cpes": [
			  "cpe:2.3:a:google:protobuf:v1.27.1:*:*:*:*:*:*:*"
			 ]
			},
			"found": {
			 "versionConstraint": "< 3.15.0 (unknown)",
			 "cpes": [
			  "cpe:2.3:a:google:protobuf:*:*:*:*:*:*:*:*"
			 ]
			}
		   }
		  ],
		  "artifact": {
		   "name": "google.golang.org/protobuf",
		   "version": "v1.27.1",
		   "type": "go-module",
		   "locations": [
			{
			 "path": "/grype",
			 "layerID": "sha256:65ea08da2c3941d8571059e12f7c48821150a89ba662c9751acf5d3664df3f86"
			}
		   ],
		   "language": "go",
		   "licenses": [],
		   "cpes": [
			"cpe:2.3:a:google:protobuf:v1.27.1:*:*:*:*:*:*:*"
		   ],
		   "purl": "pkg:golang/google.golang.org/protobuf@v1.27.1",
		   "upstreams": []
		  }
		 }
		],
		"source": {
		 "type": "image",
		 "target": {
		  "userInput": "anchore/grype",
		  "imageID": "sha256:a28988cab42062d638840c4e5d5e0c46ba6dbea526a6a3858d461c50554b2795",
		  "manifestDigest": "sha256:e3f50502292a86fc8f188336153c2e0ff9216bdf2df63c4e0323d6e163210454",
		  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		  "tags": [],
		  "imageSize": 29665751,
		  "layers": [
		   {
			"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
			"digest": "sha256:b7574c4c31a87c8530c59277dfef86aac806cf6833f862833959df6b04e996d1",
			"size": 203223
		   },
		   {
			"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
			"digest": "sha256:61857988458c05660c02dc985b7dfdff0e8083d44829a546f2a0b411354ab631",
			"size": 0
		   },
		   {
			"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
			"digest": "sha256:65ea08da2c3941d8571059e12f7c48821150a89ba662c9751acf5d3664df3f86",
			"size": 29462528
		   }
		  ],
		  "manifest": "<b64 manifest>",
		  "config": "<b64 config>",
		  "repoDigests": [
		   "index.docker.io/anchore/grype@sha256:c33bd4cbedcc4ef190abe2f24c4f70ad6ddece0ec40451415efa1dea99f3a421"
		  ],
		  "architecture": "",
		  "os": ""
		 }
		},
		"distro": {
		 "name": "",
		 "version": "",
		 "idLike": null
		},
		"descriptor": {
		 "name": "grype",
		 "version": "0.34.7",
		 "configuration": {
		  "configPath": "",
		  "output": "json",
		  "file": "",
		  "distro": "",
		  "add-cpes-if-none": false,
		  "output-template-file": "",
		  "quiet": false,
		  "check-for-app-update": true,
		  "only-fixed": false,
		  "platform": "",
		  "search": {
		   "scope": "Squashed",
		   "unindexed-archives": false,
		   "indexed-archives": true
		  },
		  "ignore": null,
		  "exclude": [],
		  "db": {
		   "cache-dir": "/.cache/grype/db",
		   "update-url": "https://toolbox-data.anchore.io/grype/databases/listing.json",
		   "ca-cert": "",
		   "auto-update": true,
		   "validate-by-hash-on-start": false
		  },
		  "dev": {
		   "profile-cpu": false,
		   "profile-mem": false
		  },
		  "fail-on-severity": "",
		  "registry": {
		   "insecure-skip-tls-verify": false,
		   "insecure-use-http": false,
		   "auth": []
		  },
		  "log": {
		   "structured": false,
		   "level": "",
		   "file": ""
		  }
		 },
		 "db": {
		  "built": "2022-04-11T08:15:09Z",
		  "schemaVersion": 3,
		  "location": "/.cache/grype/db/3",
		  "checksum": "sha256:7a2e9977d84257c4aa0010ab1e256ea31e5125cb9c567926440703e65cf463b9",
		  "error": null
		 }
		}
	   } `

	sampleReport = v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    "Grype",
			Vendor:  "Anchore Inc.",
			Version: "0.34.7",
		},
		Registry: v1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: v1alpha1.Artifact{
			Repository: "anchore/grype",
			Tag:        "latest",
		},
		Summary: v1alpha1.VulnerabilitySummary{
			CriticalCount: 0,
			HighCount:     2,
			MediumCount:   0,
			LowCount:      0,
			NoneCount:     0,
			UnknownCount:  0,
		},
		Vulnerabilities: []v1alpha1.Vulnerability{
			{
				VulnerabilityID:  "CVE-2015-5237",
				Resource:         "google.golang.org/protobuf",
				InstalledVersion: "v1.27.1",
				FixedVersion:     "",
				Severity:         v1alpha1.SeverityHigh,
				Title:            "google.golang.org/protobuf",
				Description:      "protobuf allows remote authenticated attackers to cause a heap-based buffer overflow.",
				PrimaryLink:      "https://nvd.nist.gov/vuln/detail/CVE-2015-5237",
				Score:            pointer.Float64(8.8),
				Links: []string{
					"https://github.com/google/protobuf/issues/760",
					"https://bugzilla.redhat.com/show_bug.cgi?id=1256426",
					"http://www.openwall.com/lists/oss-security/2015/08/27/2",
					"https://lists.apache.org/thread.html/b0656d359c7d40ec9f39c8cc61bca66802ef9a2a12ee199f5b0c1442@%3Cdev.drill.apache.org%3E",
					"https://lists.apache.org/thread.html/519eb0fd45642dcecd9ff74cb3e71c20a4753f7d82e2f07864b5108f@%3Cdev.drill.apache.org%3E",
					"https://lists.apache.org/thread.html/ra28fed69eef3a71e5fe5daea001d0456b05b102044237330ec5c7c82@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/f9bc3e55f4e28d1dcd1a69aae6d53e609a758e34d2869b4d798e13cc@%3Cissues.drill.apache.org%3E",
					"https://lists.apache.org/thread.html/r17dc6f394429f6bffb5e4c66555d93c2e9923cbbdc5a93db9a56c1c7@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/r42e47994734cd1980ef3e204a40555336e10cc80096927aca2f37d90@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/re6d04a214424a97ea59c62190d79316edf311a0a6346524dfef3b940@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/r1263fa5b51e4ec3cb8f09ff40e4747428c71198e9bee93349ec96a3c@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/r42ef6acfb0d86a2df0c2390702ecbe97d2104a331560f2790d17ca69@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/rb71dac1d9dd4e8a8ae3dbc033aeae514eda9be1263c1df3b42a530a2@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/r320dc858da88846ba00bb077bcca2cdf75b7dde0f6eb3a3d60dba6a1@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/r85c9a764b573c786224688cc906c27e28343e18f5b33387f94cae90f@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/r02e39d7beb32eebcdbb4b516e95f67d71c90d5d462b26f4078d21eeb@%3Cuser.flink.apache.org%3E",
					"https://lists.apache.org/thread.html/r02e39d7beb32eebcdbb4b516e95f67d71c90d5d462b26f4078d21eeb@%3Cdev.flink.apache.org%3E",
					"https://lists.apache.org/thread.html/r5e52caf41dc49df55b4ee80758356fe1ff2a88179ff24c685de7c28d@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/rf7539287c90be979bac94af9aaba34118fbf968864944b4871af48dd@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/r1d274d647b3c2060df9be21eade4ce56d3a59998cf19ac72662dd994@%3Ccommits.pulsar.apache.org%3E",
					"https://lists.apache.org/thread.html/r4886108206d4c535db9b20c813fe4723d4fe6a91b9278382af8b9d08@%3Cissues.spark.apache.org%3E",
					"https://lists.apache.org/thread.html/rb40dc9d63a5331bce8e80865b7fa3af9dd31e16555affd697b6f3526@%3Cissues.spark.apache.org%3E",
					"https://lists.apache.org/thread.html/r5741f4dbdd129dbb9885f5fb170dc1b24a06b9313bedef5e67fded94@%3Cissues.spark.apache.org%3E",
					"https://lists.apache.org/thread.html/r14fa8d38d5757254f1a2e112270c996711d514de2e3b01c93d397ab4@%3Cissues.spark.apache.org%3E",
					"https://lists.apache.org/thread.html/r2ea33ce5591a9cb9ed52750b6ab42ab658f529a7028c3166ba93c7d5@%3Ccommon-issues.hadoop.apache.org%3E",
					"https://lists.apache.org/thread.html/r00d9ab1fc0f1daf14cd4386564dd84f7889404438d81462c86dfa836@%3Ccommon-dev.hadoop.apache.org%3E",
					"https://lists.apache.org/thread.html/r764fc66435ee4d185d359c28c0887d3e5866d7292a8d5598d9e7cbc4@%3Ccommon-issues.hadoop.apache.org%3E",
					"https://lists.apache.org/thread.html/r0ca83171c4898dc92b86fa6f484a7be1dc96206765f4d01dce0f1b28@%3Ccommon-issues.hadoop.apache.org%3E",
					"https://lists.apache.org/thread.html/r00097d0b5b6164ea428554007121d5dc1f88ba2af7b9e977a10572cd@%3Cdev.hbase.apache.org%3E",
					"https://lists.apache.org/thread.html/rd64381fb8f92d640c1975dc50dcdf1b8512e02a2a7b20292d3565cae@%3Cissues.hbase.apache.org%3E",
					"https://lists.apache.org/thread.html/r4ef574a5621b0e670a3ce641e9922543e34f22bf4c9ee9584aa67fcf@%3Cissues.hbase.apache.org%3E",
					"https://lists.apache.org/thread.html/r7fed8dd9bee494094e7011cf3c2ab75bd8754ea314c6734688c42932@%3Ccommon-issues.hadoop.apache.org%3E",
				},
			},
			{
				VulnerabilityID:  "CVE-2021-22570",
				Resource:         "google.golang.org/protobuf",
				InstalledVersion: "v1.27.1",
				FixedVersion:     "",
				Severity:         v1alpha1.SeverityHigh,
				Title:            "google.golang.org/protobuf",
				Description:      "Nullptr dereference when a null char is present in a proto symbol. The symbol is parsed incorrectly, leading to an unchecked call into the proto file's name during generation of the resulting error message. Since the symbol is incorrectly parsed, the file is nullptr. We recommend upgrading to version 3.15.0 or greater.",
				PrimaryLink:      "https://nvd.nist.gov/vuln/detail/CVE-2021-22570",
				Score:            pointer.Float64(7.5),
				Links: []string{
					"https://github.com/protocolbuffers/protobuf/releases/tag/v3.15.0",
					"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IFX6KPNOFHYD6L4XES5PCM3QNSKZBOTQ/",
					"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3DVUZPALAQ34TQP6KFNLM4IZS6B32XSA/",
					"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BTRGBRC5KGCA4SK5MUNLPYJRAGXMBIYY/",
					"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NVTWVQRB5OCCTMKEQFY5MYED3DXDVSLP/",
					"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5PAGL5M2KGYPN3VEQCRJJE6NA7D5YG5X/",
					"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KQJB6ZPRLKV6WCMX2PRRRQBFAOXFBK6B/",
					"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MRWRAXAFR3JR7XCFWTHC2KALSZKWACCE/",
				},
			},
		},
	}
)

func TestPlugin_ParseVulnerabilityReportData(t *testing.T) {
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "starboard-grype-config",
			Namespace: "starboard-ns",
		},
		Data: map[string]string{
			"grype.imageRef": "anchore/grype:0.34.7",
		},
	}

	testCases := []struct {
		name           string
		imageRef       string
		input          string
		expectedError  error
		expectedReport v1alpha1.VulnerabilityReportData
	}{
		{
			name:           "Should convert vulnerability report in JSON format when input is quiet",
			imageRef:       "anchore/grype",
			input:          sampleReportAsString,
			expectedError:  nil,
			expectedReport: sampleReport,
		},
		{
			name:          "Should convert vulnerability report in JSON format when OS is not detected",
			imageRef:      "core.harbor.domain/library/nginx@sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
			input:         `null`,
			expectedError: nil,
			expectedReport: v1alpha1.VulnerabilityReportData{
				UpdateTimestamp: metav1.NewTime(fixedTime),
				Scanner: v1alpha1.Scanner{
					Name:    "Grype",
					Vendor:  "Anchore Inc.",
					Version: "0.34.7",
				},
				Registry: v1alpha1.Registry{
					Server: "core.harbor.domain",
				},
				Artifact: v1alpha1.Artifact{
					Repository: "library/nginx",
					Digest:     "sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
				},
				Summary: v1alpha1.VulnerabilitySummary{
					CriticalCount: 0,
					HighCount:     0,
					MediumCount:   0,
					LowCount:      0,
					NoneCount:     0,
					UnknownCount:  0,
				},
				Vulnerabilities: []v1alpha1.Vulnerability{},
			},
		},
		{
			name:          "Should return error when image reference cannot be parsed",
			imageRef:      ":",
			input:         "null",
			expectedError: errors.New("could not parse reference: :"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithObjects(config).Build()
			ctx := starboard.NewPluginContext().
				WithName("Grype").
				WithNamespace("starboard-ns").
				WithServiceAccountName("starboard-sa").
				WithClient(fakeClient).
				Get()
			instance := grype.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), fakeClient)
			report, err := instance.ParseVulnerabilityReportData(ctx, tc.imageRef, io.NopCloser(strings.NewReader(tc.input)))
			switch {
			case tc.expectedError == nil:
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReport, report)
			default:
				assert.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}

}
