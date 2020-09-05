package secrets_test

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/docker"

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

	Context("MapDockerRegistryServersToAuths", func() {

		It("should map Docker registry servers to Docker authentication credentials", func() {
			auths, err := secrets.MapDockerRegistryServersToAuths([]corev1.Secret{
				{
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "http://index.docker.io/v1": {
      "auth": "cm9vdDpzM2NyZXQ="
    }
  }
}`),
					},
				},
				{
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "quay.io": {
      "auth": "dXNlcjpBZG1pbjEyMzQ1"
    }
  }
}`),
					},
				},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(auths).To(MatchAllKeys(Keys{
				"index.docker.io": Equal(docker.Auth{
					Auth:     "cm9vdDpzM2NyZXQ=",
					Username: "root",
					Password: "s3cret",
				}),
				"quay.io": Equal(docker.Auth{
					Auth:     "dXNlcjpBZG1pbjEyMzQ1",
					Username: "user",
					Password: "Admin12345",
				}),
			}))
		})

	})

	Context("MapImagesToAuths", func() {

		It("should map container images to Docker authentication credentials", func() {
			auths, err := secrets.MapContainerImagesToAuths(corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "docker.io/my-organization/my-app-backend:0.1.0",
					},
					{
						Image: "my-organization/my-app-frontend:0.3.2",
					},
					{
						Image: "quay.io/my-company/my-service:2.0",
					},
				},
			}, []corev1.Secret{
				{
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "http://index.docker.io/v1": {
      "auth": "cm9vdDpzM2NyZXQ="
    }
  }
}`),
					},
				},
				{
					Type: corev1.SecretTypeDockerConfigJson,
					Data: map[string][]byte{
						corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "quay.io": {
      "auth": "dXNlcjpBZG1pbjEyMzQ1"
    }
  }
}`),
					},
				},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(auths).To(MatchAllKeys(Keys{
				"docker.io/my-organization/my-app-backend:0.1.0": Equal(docker.Auth{
					Auth:     "cm9vdDpzM2NyZXQ=",
					Username: "root",
					Password: "s3cret",
				}),
				"my-organization/my-app-frontend:0.3.2": Equal(docker.Auth{
					Auth:     "cm9vdDpzM2NyZXQ=",
					Username: "root",
					Password: "s3cret",
				}),
				"quay.io/my-company/my-service:2.0": Equal(docker.Auth{
					Auth:     "dXNlcjpBZG1pbjEyMzQ1",
					Username: "user",
					Password: "Admin12345",
				}),
			}))
		})

	})

})
