package secret

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/docker"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// TODO Refactor so we don't use the kubernetes.Interface but rather Secrets and imageRefs values.
type Manager struct {
	clientset kubernetes.Interface
}

// NewSecretManager constructs new Manager with the specified Kubernetes Clientset.
func NewSecretManager(clientset kubernetes.Interface) *Manager {
	return &Manager{
		clientset: clientset,
	}
}

// GetImagesWithCredentials gets private images for the specified PodSpec and maps them to the Docker ServerCredentials.
func (s *Manager) GetImagesWithCredentials(ctx context.Context, namespace string, spec corev1.PodSpec) (credentials map[string]docker.Auth, err error) {
	images := s.GetImages(spec)

	serverCredentials, err := s.GetRegistryHostsWithCredentials(ctx, namespace, spec.ImagePullSecrets)
	if err != nil {
		return
	}

	credentials = make(map[string]docker.Auth)
	for _, image := range images {
		server, err := docker.GetServerFromImageRef(image)
		if err != nil {
			return nil, fmt.Errorf("getting registry from image reference: %s: %w", image, err)
		}
		if ce, ok := serverCredentials[server]; ok {
			credentials[image] = ce
		}
	}

	return
}

// GetImages gets a slice of images for the specified PodSpec.
func (s *Manager) GetImages(spec corev1.PodSpec) (images []string) {
	for _, c := range spec.InitContainers {
		images = append(images, c.Image)
	}

	for _, c := range spec.Containers {
		images = append(images, c.Image)
	}

	return
}

func (s *Manager) GetRegistryHostsWithCredentials(ctx context.Context, namespace string, imagePullSecrets []corev1.LocalObjectReference) (credentials map[string]docker.Auth, err error) {
	credentials = make(map[string]docker.Auth)

	for _, secret := range imagePullSecrets {
		secret, err := s.clientset.CoreV1().
			Secrets(namespace).
			Get(ctx, secret.Name, metav1.GetOptions{})

		if err != nil {
			return nil, err
		}
		dockerConfig := &docker.Config{}
		err = dockerConfig.Read(secret.Data[corev1.DockerConfigJsonKey])
		if err != nil {
			return nil, err
		}
		for server, auth := range dockerConfig.Auths {
			host, err := docker.GetHostFromServer(server)
			if err != nil {
				return nil, err
			}
			credentials[host] = auth
		}
	}

	return
}
