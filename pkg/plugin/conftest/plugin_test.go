package conftest_test

import (
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/plugin/conftest"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

func TestPlugin_GetScanJobSpec(t *testing.T) {
	g := NewGomegaWithT(t)
	sequence := ext.NewSimpleIDGenerator()
	config := starboard.ConfigData{
		"conftest.imageRef": "openpolicyagent/conftest:v0.23.0",
	}
	pluginContext := starboard.NewPluginContext().
		WithName(string(starboard.Conftest)).
		WithNamespace(starboard.NamespaceName).
		WithServiceAccountName(starboard.ServiceAccountName).
		WithClient(fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "starboard-conftest-config",
				Namespace: starboard.NamespaceName,
			},
			Data: map[string]string{
				"conftest.policy.kubernetes.rego":   "<REGO>",
				"conftest.policy.first_check.rego":  "<REGO>",
				"conftest.policy.second_check.rego": "<REGO>",
			},
		}).Build()).Build()

	plugin := conftest.NewPlugin(sequence, fixedClock, config)
	jobSpec, secrets, err := plugin.GetScanJobSpec(pluginContext, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.16",
				},
			},
		},
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(secrets).To(HaveLen(1))
	g.Expect(jobSpec).To(MatchFields(IgnoreExtras, Fields{
		"ServiceAccountName":           Equal("starboard"),
		"AutomountServiceAccountToken": PointTo(BeFalse()),
		"RestartPolicy":                Equal(corev1.RestartPolicyNever),
		"Affinity":                     Equal(starboard.LinuxNodeAffinity()),
		// TODO Assert other properties
	}))
}

func TestPlugin_GetConfigHash(t *testing.T) {

	newPluginContextWithConfigData := func(data map[string]string) starboard.PluginContext {
		return starboard.NewPluginContext().
			WithName("Conftest").
			WithNamespace("starboard-ns").
			WithClient(fake.NewClientBuilder().
				WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "starboard-conftest-config",
						Namespace: "starboard-ns",
					},
					Data: data,
				}).
				Build()).
			Build()
	}

	t.Run("Should return different hash for different config data", func(t *testing.T) {
		g := NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":   "bar",
			"brown": "fox",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"brown": "fox",
			"foo":   "baz",
		})

		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock, starboard.ConfigData{})
		hash1, err := plugin.GetConfigHash(pluginContext1)
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.GetConfigHash(pluginContext2)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).ToNot(Equal(hash2))
	})

	t.Run("Should return the same hash for the same config data", func(t *testing.T) {
		g := NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":   "bar",
			"brown": "fox",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"brown": "fox",
			"foo":   "bar",
		})

		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock, starboard.ConfigData{})
		hash1, err := plugin.GetConfigHash(pluginContext1)
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.GetConfigHash(pluginContext2)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).To(Equal(hash2))
	})
}

func TestPlugin_GetContainerName(t *testing.T) {
	g := NewGomegaWithT(t)

	plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock, starboard.ConfigData{})
	g.Expect(plugin.GetContainerName()).To(Equal("conftest"))
}
