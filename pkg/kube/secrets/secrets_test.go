package secrets_test

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/kube/secrets"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSecrets(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Secrets")
}

var _ = Describe("Secrets", func() {

	Context("NewImagePullSecret", func() {

		It("should construct a new image secret with encoded data", func() {
			secret, err := secrets.NewImagePullSecret(metav1.ObjectMeta{
				Name:      "my-secret",
				Namespace: "my-namespace",
			}, "http://index.docker.io/v1", "root", "s3cret")

			Expect(err).ToNot(HaveOccurred())
			Expect(*secret).To(MatchFields(IgnoreExtras, Fields{
				"ObjectMeta": MatchFields(IgnoreExtras, Fields{
					"Name":      Equal("my-secret"),
					"Namespace": Equal("my-namespace"),
				}),
				"Type": Equal(corev1.SecretTypeDockerConfigJson),
				"Data": MatchAllKeys(Keys{
					".dockerconfigjson": MatchJSON(`{
  "auths": {
    "http://index.docker.io/v1": {
      "auth": "cm9vdDpzM2NyZXQ=",
      "username": "root",
      "password": "s3cret"
    }
  }
}`),
				}),
			}))
		})

	})

})
