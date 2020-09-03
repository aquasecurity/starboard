package secrets

import (
	"github.com/aquasecurity/starboard/pkg/docker"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
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

// MapImagesToAuths creates the mapping from a container image to the Docker authentication
// credentials for the specified PodSpec and the slice of image pull Secrets.
func MapContainerImagesToAuths(spec corev1.PodSpec, imagePullSecrets []corev1.Secret) (map[string]docker.Auth, error) {
	auths, err := MapDockerRegistryServersToAuths(imagePullSecrets)
	if err != nil {
		return nil, err
	}

	mapping := make(map[string]docker.Auth)

	for _, image := range pod.GetImages(spec) {
		server, err := docker.GetServerFromImageRef(image)
		if err != nil {
			return nil, err
		}
		if auth, ok := auths[server]; ok {
			mapping[image] = auth
		}
	}

	return mapping, nil
}

// MapDockerRegistryServersToAuths creates the mapping from a Docker registry server
// to the Docker authentication credentials for the specified slice of image pull Secrets.
func MapDockerRegistryServersToAuths(imagePullSecrets []corev1.Secret) (map[string]docker.Auth, error) {
	auths := make(map[string]docker.Auth)
	for _, secret := range imagePullSecrets {
		dockerConfig := &docker.Config{}
		err := dockerConfig.Read(secret.Data[corev1.DockerConfigJsonKey])
		if err != nil {
			return nil, err
		}
		for server, auth := range dockerConfig.Auths {
			host, err := docker.GetHostFromServer(server)
			if err != nil {
				return nil, err
			}
			auths[host] = auth
		}
	}
	return auths, nil
}
