package secret

import (
	"context"
	"strings"

	"github.com/aquasecurity/starboard/pkg/docker"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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
func (s *Manager) GetImagesWithCredentials(ctx context.Context, namespace string, spec core.PodSpec) (credentials map[string]docker.ServerCredentials, err error) {
	images := s.GetImages(spec)

	serverCredentials, err := s.GetServersWithCredentials(ctx, namespace, spec.ImagePullSecrets)
	if err != nil {
		return
	}

	credentials = make(map[string]docker.ServerCredentials)
	for _, image := range images {
		server := s.GetServerFromImage(image)
		if ce, ok := serverCredentials[server]; ok {
			credentials[image] = ce
		}
	}

	return
}

// GetImages gets a slice of images for the specified PodSpec.
func (s *Manager) GetImages(spec core.PodSpec) (images []string) {
	for _, c := range spec.InitContainers {
		images = append(images, c.Image)
	}

	for _, c := range spec.Containers {
		images = append(images, c.Image)
	}

	return
}

func (s *Manager) GetServersWithCredentials(ctx context.Context, namespace string, imagePullSecrets []core.LocalObjectReference) (credentials map[string]docker.ServerCredentials, err error) {
	credentials = make(map[string]docker.ServerCredentials)

	for _, secret := range imagePullSecrets {
		secret, err := s.clientset.CoreV1().
			Secrets(namespace).
			Get(ctx, secret.Name, meta.GetOptions{})

		if err != nil {
			return nil, err
		}
		dockerCfg, err := docker.ReadCredentialsFromBytes(secret.Data[".dockerconfigjson"])
		for server, configEntry := range dockerCfg {
			credentials[server] = configEntry
		}
	}

	return
}

func (s *Manager) GetServerFromImage(image string) string {
	chunks := strings.Split(image, "/")
	if len(chunks) > 0 {
		return chunks[0]
	}
	return ""
}
