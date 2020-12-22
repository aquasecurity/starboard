package starboard_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/starboard/pkg/starboard"
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

	t.Run("Should create ConfigMap with default values, and empty secret", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()

		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).EnsureDefault(context.TODO())
		require.NoError(t, err)

		cm, err := clientset.CoreV1().
			ConfigMaps(starboard.NamespaceName).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, starboard.GetDefaultConfig(), starboard.ConfigData(cm.Data))

		secret, err := clientset.CoreV1().
			Secrets(starboard.NamespaceName).
			Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, map[string][]byte(nil), secret.Data)
	})

	t.Run("Should not modify ConfigMap nor secret if they already exist", func(t *testing.T) {
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

		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).EnsureDefault(context.TODO())
		require.NoError(t, err)

		cm, err := clientset.CoreV1().
			ConfigMaps(starboard.NamespaceName).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			"foo": "bar",
		}, cm.Data)

		secret, err := clientset.CoreV1().
			Secrets(starboard.NamespaceName).
			Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, map[string][]byte{
			"baz": []byte("s3cret"),
		}, secret.Data)
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
