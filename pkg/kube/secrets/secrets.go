package secrets

import (
	"github.com/aquasecurity/starboard/pkg/docker"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NewImagePullSecret constructs a new image pull Secret with the specified
// registry server and basic authentication credentials.
func NewImagePullSecret(meta metav1.ObjectMeta, server, username, password string) (*corev1.Secret, error) {
	dockerConfig, err := docker.Config{
		Auths: map[string]docker.Auth{
			server: {
				Username: username,
				Password: password,
				Auth:     docker.NewBasicAuth(username, password),
			},
		},
	}.Write()
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: meta,
		Type:       corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: dockerConfig,
		},
	}, nil
}
