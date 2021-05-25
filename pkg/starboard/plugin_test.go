package starboard_test

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetPluginConfigMapName(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	name := starboard.GetPluginConfigMapName("Conftest")
	g.Expect(name).To(gomega.Equal("starboard-conftest-config"))
}

func TestPluginContext_GetConfig(t *testing.T) {

	t.Run("Should return PluginConfig from ConfigMap", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		client := fake.NewClientBuilder().
			WithScheme(starboard.NewScheme()).
			WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "starboard-polaris-config",
					Namespace: "starboard-ns",
				},
				Data: map[string]string{
					"foo": "bar",
				},
			}).
			Build()

		pluginContext := starboard.NewPluginContext().
			WithName("polaris").
			WithNamespace("starboard-ns").
			WithClient(client).
			Get()

		cm, err := pluginContext.GetConfig()

		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm).To(gomega.Equal(
			starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}))
	})

	t.Run("Should return PluginConfig from ConfigMap and Secret", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		client := fake.NewClientBuilder().
			WithScheme(starboard.NewScheme()).
			WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "starboard-polaris-config",
					Namespace: "starboard-ns",
				},
				Data: map[string]string{
					"foo": "bar",
				},
			}, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "starboard-polaris-config",
					Namespace: "starboard-ns",
				},
				Data: map[string][]byte{
					"secret": []byte("pa$$word"),
				},
			}).
			Build()

		pluginContext := starboard.NewPluginContext().
			WithName("polaris").
			WithNamespace("starboard-ns").
			WithClient(client).
			Get()

		cm, err := pluginContext.GetConfig()

		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm).To(gomega.Equal(
			starboard.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
				SecretData: map[string][]byte{
					"secret": []byte("pa$$word"),
				},
			}))
	})
}
