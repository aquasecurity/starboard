package starboard_test

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
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
		expectedImageRef string
	}{
		{
			name:             "Should return default image reference",
			configData:       starboard.ConfigData{},
			expectedImageRef: "docker.io/aquasec/trivy:0.9.1",
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
			imageRef := tc.configData.GetTrivyImageRef()
			assert.Equal(t, tc.expectedImageRef, imageRef)
		})
	}
}

func TestConfigData_GetKubeBenchImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       starboard.ConfigData
		expectedImageRef string
	}{
		{
			name:             "Should return default image reference",
			configData:       starboard.ConfigData{},
			expectedImageRef: "docker.io/aquasec/kube-bench:0.4.0",
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
			imageRef := tc.configData.GetKubeBenchImageRef()
			assert.Equal(t, tc.expectedImageRef, imageRef)
		})
	}
}

func TestConfigManager_Read(t *testing.T) {
	clientset := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: starboard.NamespaceName,
			Name:      starboard.ConfigMapName,
		},
		Data: map[string]string{
			"foo": "bar",
		},
	})
	configData, err := starboard.NewConfigManager(clientset, starboard.NamespaceName).Read(context.TODO())
	require.NoError(t, err)
	assert.Equal(t, starboard.ConfigData{
		"foo": "bar",
	}, configData)
}

func TestConfigManager_EnsureDefault(t *testing.T) {

	t.Run("Should create the ConfigMap with the default configuration settings", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()

		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).EnsureDefault(context.TODO())
		require.NoError(t, err)

		cm, err := clientset.CoreV1().
			ConfigMaps(starboard.NamespaceName).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, starboard.GetDefaultConfig(), starboard.ConfigData(cm.Data))
	})

	t.Run("Should not modify the ConfigMap if it already exists", func(t *testing.T) {
		clientset := fake.NewSimpleClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: starboard.NamespaceName,
				Name:      starboard.ConfigMapName,
			},
			Data: map[string]string{
				"foo": "bar",
			},
		})

		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).EnsureDefault(context.TODO())
		require.NoError(t, err)

		cm, err := clientset.CoreV1().
			ConfigMaps(starboard.NamespaceName).
			Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)

		assert.Equal(t, map[string]string{
			"foo": "bar",
		}, cm.Data)
	})

}

func TestConfigManager_Delete(t *testing.T) {

	t.Run("Should not return error when ConfigMap does not exist", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()
		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).Delete(context.TODO())
		require.NoError(t, err)
	})

	t.Run("Should delete the ConfigMap", func(t *testing.T) {
		clientset := fake.NewSimpleClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: starboard.NamespaceName,
				Name:      starboard.ConfigMapName,
			},
			Data: map[string]string{
				"foo": "bar",
			},
		})

		err := starboard.NewConfigManager(clientset, starboard.NamespaceName).Delete(context.TODO())
		require.NoError(t, err)

		_, err = clientset.CoreV1().ConfigMaps(starboard.NamespaceName).Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
		assert.True(t, errors.IsNotFound(err))
	})
}
