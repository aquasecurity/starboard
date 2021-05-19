package starboard_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetVersionFromImageRef(t *testing.T) {
	testCases := []struct {
		imageRef        string
		expectedVersion string
	}{
		{
			imageRef:        "docker.io/aquasec/trivy:0.9.1",
			expectedVersion: "0.9.1",
		},
		{
			imageRef:        "docker.io/aquasec/trivy@sha256:5020dac24a63ef4f24452a0c63ebbfe93a5309e40f6353d1ee8221d2184ee954",
			expectedVersion: "sha256:5020dac24a63ef4f24452a0c63ebbfe93a5309e40f6353d1ee8221d2184ee954",
		},
		{
			imageRef:        "aquasec/trivy:0.9.1",
			expectedVersion: "0.9.1",
		},
		{
			imageRef:        "aquasec/trivy:latest",
			expectedVersion: "latest",
		},
		{
			imageRef:        "aquasec/trivy",
			expectedVersion: "latest",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.imageRef, func(t *testing.T) {
			version, _ := starboard.GetVersionFromImageRef(tc.imageRef)
			assert.Equal(t, tc.expectedVersion, version)
		})
	}
}

func TestConfigData_GetTrivyImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       starboard.ConfigData
		expectedError    string
		expectedImageRef string
	}{
		{
			name:          "Should return error",
			configData:    starboard.ConfigData{},
			expectedError: "property trivy.imageRef not set",
		},
		{
			name: "Should return image reference from config data",
			configData: starboard.ConfigData{
				"trivy.imageRef": "gcr.io/aquasecurity/trivy:0.8.0",
			},
			expectedImageRef: "gcr.io/aquasecurity/trivy:0.8.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageRef, err := tc.configData.GetTrivyImageRef()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedImageRef, imageRef)
			}
		})
	}
}

func TestConfigData_GetKubeBenchImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       starboard.ConfigData
		expectedError    string
		expectedImageRef string
	}{
		{
			name:          "Should return error",
			configData:    starboard.ConfigData{},
			expectedError: "property kube-bench.imageRef not set",
		},
		{
			name: "Should return image reference from config data",
			configData: starboard.ConfigData{
				"kube-bench.imageRef": "gcr.io/aquasecurity/kube-bench:0.4.0",
			},
			expectedImageRef: "gcr.io/aquasecurity/kube-bench:0.4.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageRef, err := tc.configData.GetKubeBenchImageRef()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedImageRef, imageRef)
			}
		})
	}
}

func TestConfigData_GetKubeHunterImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       starboard.ConfigData
		expectedError    string
		expectedImageRef string
	}{
		{
			name:          "Should return error",
			configData:    starboard.ConfigData{},
			expectedError: "property kube-hunter.imageRef not set",
		},
		{
			name: "Should return image reference from config data",
			configData: starboard.ConfigData{
				"kube-hunter.imageRef": "gcr.io/aquasecurity/kube-hunter:0.4.0",
			},
			expectedImageRef: "gcr.io/aquasecurity/kube-hunter:0.4.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageRef, err := tc.configData.GetKubeHunterImageRef()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedImageRef, imageRef)
			}
		})
	}
}

func TestConfigData_GetKubeHunterQuick(t *testing.T) {
	testCases := []struct {
		name          string
		configData    starboard.ConfigData
		expectedError string
		expectedQuick bool
	}{
		{
			name:          "Should return false when parameter is not set",
			configData:    starboard.ConfigData{},
			expectedQuick: false,
		}, {
			name: "Should return error when quick is set to something other than \"false\" or \"true\" in config data",
			configData: starboard.ConfigData{
				"kube-hunter.quick": "not-a-boolean",
			},
			expectedError: "property kube-hunter.quick must be either \"false\" or \"true\", got \"not-a-boolean\"",
		}, {
			name: "Should return false when quick is set to \"false\" in config data",
			configData: starboard.ConfigData{
				"kube-hunter.quick": "false",
			},
			expectedQuick: false,
		},
		{
			name: "Should return true when quick is set to \"true\" in config data",
			configData: starboard.ConfigData{
				"kube-hunter.quick": "true",
			},
			expectedQuick: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			quick, err := tc.configData.GetKubeHunterQuick()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedQuick, quick)
			}
		})
	}
}

func TestConfigData_GetVulnerabilityReportsScanner(t *testing.T) {
	testCases := []struct {
		name            string
		configData      starboard.ConfigData
		expectedError   string
		expectedScanner starboard.Scanner
	}{
		{
			name: "Should return Trivy",
			configData: starboard.ConfigData{
				"vulnerabilityReports.scanner": "Trivy",
			},
			expectedScanner: starboard.Trivy,
		},
		{
			name: "Should return Aqua",
			configData: starboard.ConfigData{
				"vulnerabilityReports.scanner": "Aqua",
			},
			expectedScanner: starboard.Aqua,
		},
		{
			name:          "Should return error when value is not set",
			configData:    starboard.ConfigData{},
			expectedError: "property vulnerabilityReports.scanner not set",
		},
		{
			name: "Should return error when value is not allowed",
			configData: starboard.ConfigData{
				"vulnerabilityReports.scanner": "Clair",
			},
			expectedError: "invalid value (Clair) of vulnerabilityReports.scanner; allowed values (Trivy, Aqua)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := tc.configData.GetVulnerabilityReportsScanner()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedScanner, scanner)
			}
		})
	}
}

func TestConfigData_GetTrivyMode(t *testing.T) {
	testCases := []struct {
		name          string
		configData    starboard.ConfigData
		expectedError string
		expectedMode  starboard.TrivyMode
	}{
		{
			name: "Should return Standalone",
			configData: starboard.ConfigData{
				"trivy.mode": "Standalone",
			},
			expectedMode: starboard.Standalone,
		},
		{
			name: "Should return ClientServer",
			configData: starboard.ConfigData{
				"trivy.mode": "ClientServer",
			},
			expectedMode: starboard.ClientServer,
		},
		{
			name:          "Should return error when value is not set",
			configData:    starboard.ConfigData{},
			expectedError: "property trivy.mode not set",
		},
		{
			name: "Should return error when value is not allowed",
			configData: starboard.ConfigData{
				"trivy.mode": "P2P",
			},
			expectedError: "invalid value (P2P) of trivy.mode; allowed values (Standalone, ClientServer)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := tc.configData.GetTrivyMode()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedMode, mode)
			}
		})
	}
}

func TestConfigManager_Read(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: starboard.NamespaceName,
				Name:      starboard.ConfigMapName,
			},
			Data: map[string]string{
				"foo": "bar",
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: starboard.NamespaceName,
				Name:      starboard.SecretName,
			},
			Data: map[string][]byte{
				"baz": []byte("s3cret"),
			},
		},
	)

	data, err := starboard.NewConfigManager(clientset, starboard.NamespaceName).
		Read(context.TODO())

	require.NoError(t, err)
	assert.Equal(t, starboard.ConfigData{
		"foo": "bar",
		"baz": "s3cret",
	}, data)
}

func TestConfigManager_EnsureDefault(t *testing.T) {

	t.Run("Should create ConfigMaps and Secret", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		namespace := "starboard-ns"
		clientset := fake.NewSimpleClientset()

		err := starboard.NewConfigManager(clientset, namespace).EnsureDefault(context.TODO())
		g.Expect(err).ToNot(gomega.HaveOccurred())

		cm, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm.Data).To(gomega.BeEquivalentTo(starboard.GetDefaultConfig()))

		secret, err := clientset.CoreV1().Secrets(namespace).
			Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(secret.Data).To(gomega.BeEmpty())

		pluginConfig, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.GetPluginConfigMapName(string(starboard.Polaris)), metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(pluginConfig.Data).To(gomega.Equal(starboard.GetDefaultPolarisConfig()))

		_, err = clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.GetPluginConfigMapName(string(starboard.Conftest)), metav1.GetOptions{})
		g.Expect(err).To(gomega.MatchError(`configmaps "starboard-conftest-config" not found`))
	})

	t.Run("Should not modify ConfigMaps nor Secret", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)
		namespace := "starboard-ns"
		clientset := fake.NewSimpleClientset(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      starboard.ConfigMapName,
				},
				Data: map[string]string{
					"foo":                        "bar",
					"configAuditReports.scanner": string(starboard.Conftest),
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      starboard.SecretName,
				},
				Data: map[string][]byte{
					"baz": []byte("s3cret"),
				},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      starboard.GetPluginConfigMapName(string(starboard.Conftest)),
				},
				Data: map[string]string{
					"conftest.policy.my-check.rego": "<REGO>",
				},
			},
		)

		err := starboard.NewConfigManager(clientset, namespace).EnsureDefault(context.TODO())
		g.Expect(err).ToNot(gomega.HaveOccurred())

		cm, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm.Data).To(gomega.Equal(map[string]string{
			"foo":                        "bar",
			"configAuditReports.scanner": "Conftest",
		}))

		secret, err := clientset.CoreV1().Secrets(namespace).
			Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(secret.Data).To(gomega.Equal(map[string][]byte{
			"baz": []byte("s3cret"),
		}))

		pluginConfig, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.GetPluginConfigMapName(string(starboard.Conftest)), metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(pluginConfig.Data).To(gomega.Equal(map[string]string{
			"conftest.policy.my-check.rego": "<REGO>",
		}))

		_, err = clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.GetPluginConfigMapName(string(starboard.Polaris)), metav1.GetOptions{})
		g.Expect(err).To(gomega.MatchError(`configmaps "starboard-polaris-config" not found`))
	})

	t.Run("Should create ConfigMap for Polaris", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)
		namespace := "starboard-ns"
		clientset := fake.NewSimpleClientset(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      starboard.ConfigMapName,
				},
				Data: map[string]string{
					"foo":                        "bar",
					"configAuditReports.scanner": string(starboard.Polaris),
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      starboard.SecretName,
				},
				Data: map[string][]byte{
					"baz": []byte("s3cret"),
				},
			},
		)

		err := starboard.NewConfigManager(clientset, namespace).EnsureDefault(context.TODO())
		g.Expect(err).ToNot(gomega.HaveOccurred())

		cm, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm.Data).To(gomega.Equal(map[string]string{
			"foo":                        "bar",
			"configAuditReports.scanner": "Polaris",
		}))

		secret, err := clientset.CoreV1().Secrets(namespace).
			Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(secret.Data).To(gomega.Equal(map[string][]byte{
			"baz": []byte("s3cret"),
		}))

		pluginConfig, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.GetPluginConfigMapName(string(starboard.Polaris)), metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(pluginConfig.Data).To(gomega.Equal(starboard.GetDefaultPolarisConfig()))

		_, err = clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.GetPluginConfigMapName(string(starboard.Conftest)), metav1.GetOptions{})
		g.Expect(err).To(gomega.MatchError(`configmaps "starboard-conftest-config" not found`))
	})

	t.Run("Should create ConfigMap for Conftest", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)
		namespace := "starboard-ns"
		clientset := fake.NewSimpleClientset(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      starboard.ConfigMapName,
				},
				Data: map[string]string{
					"foo":                        "bar",
					"configAuditReports.scanner": string(starboard.Conftest),
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      starboard.SecretName,
				},
				Data: map[string][]byte{
					"baz": []byte("s3cret"),
				},
			},
		)

		err := starboard.NewConfigManager(clientset, namespace).EnsureDefault(context.TODO())
		g.Expect(err).ToNot(gomega.HaveOccurred())

		cm, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm.Data).To(gomega.Equal(map[string]string{
			"foo":                        "bar",
			"configAuditReports.scanner": "Conftest",
		}))

		secret, err := clientset.CoreV1().Secrets(namespace).
			Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(secret.Data).To(gomega.Equal(map[string][]byte{
			"baz": []byte("s3cret"),
		}))

		pluginConfig, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.GetPluginConfigMapName(string(starboard.Conftest)), metav1.GetOptions{})
		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(pluginConfig.Data).To(gomega.BeEmpty())

		_, err = clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), starboard.GetPluginConfigMapName(string(starboard.Polaris)), metav1.GetOptions{})
		g.Expect(err).To(gomega.MatchError(`configmaps "starboard-polaris-config" not found`))
	})
}

func TestConfigManager_Delete(t *testing.T) {

	t.Run("Should not return error when ConfigMap and secret do not exist", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()
		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).Delete(context.TODO())
		require.NoError(t, err)
	})

	t.Run("Should delete ConfigMap and secret", func(t *testing.T) {
		clientset := fake.NewSimpleClientset(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: starboard.NamespaceName,
					Name:      starboard.ConfigMapName,
				},
				Data: map[string]string{
					"foo": "bar",
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: starboard.NamespaceName,
					Name:      starboard.SecretName,
				},
				Data: map[string][]byte{
					"baz": []byte("s3cret"),
				},
			},
		)

		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).Delete(context.TODO())
		require.NoError(t, err)

		_, err = clientset.CoreV1().ConfigMaps(starboard.NamespaceName).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		assert.True(t, errors.IsNotFound(err))

		_, err = clientset.CoreV1().Secrets(starboard.NamespaceName).
			Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
		assert.True(t, errors.IsNotFound(err))
	})
}

func TestConfigData_GetTrivyInsecureRegistries(t *testing.T) {
	testCases := []struct {
		name           string
		configData     starboard.ConfigData
		expectedOutput map[string]bool
	}{
		{
			name: "Should return nil map when there is no key with trivy.insecureRegistry. prefix",
			configData: starboard.ConfigData{
				"foo": "bar",
			},
			expectedOutput: make(map[string]bool),
		},
		{
			name: "Should return insecure registries in map",
			configData: starboard.ConfigData{
				"foo":                                "bar",
				"trivy.insecureRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"trivy.insecureRegistry.qaRegistry":  "qa.registry.aquasec.com",
			},
			expectedOutput: map[string]bool{
				"poc.myregistry.harbor.com.pl": true,
				"qa.registry.aquasec.com":      true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			insecureRegistries := tc.configData.GetTrivyInsecureRegistries()
			assert.Equal(t, tc.expectedOutput, insecureRegistries)
		})
	}
}

func TestGetScanJobTolerations(t *testing.T) {
	testcases := []struct {
		name        string
		config      starboard.ConfigData
		expected    []corev1.Toleration
		expectError string
	}{
		{
			name:     "no scanJob.tolerations in ConfigData",
			config:   starboard.ConfigData{},
			expected: []corev1.Toleration{},
		},
		{
			name:        "scanJob.tolerations value is not json",
			config:      starboard.ConfigData{"scanJob.tolerations": `lolwut`},
			expected:    []corev1.Toleration{},
			expectError: "invalid character 'l' looking for beginning of value",
		},
		{
			name:     "empty JSON array",
			config:   starboard.ConfigData{"scanJob.tolerations": `[]`},
			expected: []corev1.Toleration{},
		},
		{
			name: "one valid toleration",
			config: starboard.ConfigData{
				"scanJob.tolerations": `[{"key":"key1","operator":"Equal","value":"value1","effect":"NoSchedule"}]`},
			expected: []corev1.Toleration{{
				Key:      "key1",
				Operator: "Equal",
				Value:    "value1",
				Effect:   "NoSchedule",
			}},
		},
		{
			name: "multiple valid tolerations",
			config: starboard.ConfigData{
				"scanJob.tolerations": `[{"key":"key1","operator":"Equal","value":"value1","effect":"NoSchedule"},
					  {"key":"key2","operator":"Equal","value":"value2","effect":"NoSchedule"}]`},
			expected: []corev1.Toleration{
				{
					Key:      "key1",
					Operator: "Equal",
					Value:    "value1",
					Effect:   "NoSchedule",
				},
				{
					Key:      "key2",
					Operator: "Equal",
					Value:    "value2",
					Effect:   "NoSchedule",
				},
			},
		},
	}

	for _, tc := range testcases {
		got, err := tc.config.GetScanJobTolerations()
		if tc.expectError != "" {
			assert.Error(t, err, "unexpected end of JSON input", tc.name)
		} else {
			assert.NoError(t, err, tc.name)
		}
		assert.Equal(t, tc.expected, got, tc.name)
	}
}

func TestConfigData_TrivyIgnoreFileExists(t *testing.T) {
	testCases := []struct {
		name           string
		configData     starboard.ConfigData
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: starboard.ConfigData{
				"foo": "bar",
			},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: starboard.ConfigData{
				"foo": "bar",
				"trivy.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
			},
			expectedOutput: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exists := tc.configData.TrivyIgnoreFileExists()
			assert.Equal(t, tc.expectedOutput, exists)
		})
	}
}
