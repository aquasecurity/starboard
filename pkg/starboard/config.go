package starboard

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/google/go-containerregistry/pkg/name"
)

const (
	polarisConfigYAML = `checks:
  # reliability
  multipleReplicasForDeployment: ignore
  priorityClassNotSet: ignore
  # resources
  cpuRequestsMissing: warning
  cpuLimitsMissing: warning
  memoryRequestsMissing: warning
  memoryLimitsMissing: warning
  # images
  tagNotSpecified: danger
  pullPolicyNotAlways: ignore
  # healthChecks
  readinessProbeMissing: warning
  livenessProbeMissing: warning
  # networking
  hostNetworkSet: warning
  hostPortSet: warning
  # security
  hostIPCSet: danger
  hostPIDSet: danger
  notReadOnlyRootFilesystem: warning
  privilegeEscalationAllowed: danger
  runAsRootAllowed: warning
  runAsPrivileged: danger
  dangerousCapabilities: danger
  insecureCapabilities: warning
exemptions:
  - controllerNames:
    - kube-apiserver
    - kube-proxy
    - kube-scheduler
    - etcd-manager-events
    - kube-controller-manager
    - kube-dns
    - etcd-manager-main
    rules:
    - hostPortSet
    - hostNetworkSet
    - readinessProbeMissing
    - livenessProbeMissing
    - cpuRequestsMissing
    - cpuLimitsMissing
    - memoryRequestsMissing
    - memoryLimitsMissing
    - runAsRootAllowed
    - runAsPrivileged
    - notReadOnlyRootFilesystem
    - hostPIDSet
  - controllerNames:
    - kube-flannel-ds
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - notReadOnlyRootFilesystem
    - readinessProbeMissing
    - livenessProbeMissing
    - cpuLimitsMissing
  - controllerNames:
    - cert-manager
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
  - controllerNames:
    - cluster-autoscaler
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - readinessProbeMissing
  - controllerNames:
    - vpa
    rules:
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
    - notReadOnlyRootFilesystem
  - controllerNames:
    - datadog
    rules:
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
    - notReadOnlyRootFilesystem
  - controllerNames:
    - nginx-ingress-controller
    rules:
    - privilegeEscalationAllowed
    - insecureCapabilities
    - runAsRootAllowed
  - controllerNames:
    - dns-controller
    - datadog-datadog
    - kube-flannel-ds
    - kube2iam
    - aws-iam-authenticator
    - datadog
    - kube2iam
    rules:
    - hostNetworkSet
  - controllerNames:
    - aws-iam-authenticator
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - dnsmasq
    - autoscaler
    - kubernetes-dashboard
    - install-cni
    - kube2iam
    rules:
    - readinessProbeMissing
    - livenessProbeMissing
  - controllerNames:
    - aws-iam-authenticator
    - nginx-ingress-default-backend
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - kubedns
    - dnsmasq
    - autoscaler
    - tiller
    - kube2iam
    rules:
    - runAsRootAllowed
  - controllerNames:
    - aws-iam-authenticator
    - nginx-ingress-controller
    - nginx-ingress-default-backend
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - kubedns
    - dnsmasq
    - autoscaler
    - tiller
    - kube2iam
    rules:
    - notReadOnlyRootFilesystem
  - controllerNames:
    - cert-manager
    - dns-controller
    - kubedns
    - dnsmasq
    - autoscaler
    - insights-agent-goldilocks-vpa-install
    - datadog
    rules:
    - cpuRequestsMissing
    - cpuLimitsMissing
    - memoryRequestsMissing
    - memoryLimitsMissing
  - controllerNames:
    - kube2iam
    - kube-flannel-ds
    rules:
    - runAsPrivileged
  - controllerNames:
    - kube-hunter
    rules:
    - hostPIDSet
  - controllerNames:
    - polaris
    - kube-hunter
    - goldilocks
    - insights-agent-goldilocks-vpa-install
    rules:
    - notReadOnlyRootFilesystem
  - controllerNames:
    - insights-agent-goldilocks-controller
    rules:
    - livenessProbeMissing
    - readinessProbeMissing
  - controllerNames:
    - insights-agent-goldilocks-vpa-install
    - kube-hunter
    rules:
    - runAsRootAllowed
`
)

// BuildInfo holds build info such as Git revision, Git SHA-1,
// and build datetime.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// ConfigData holds Starboard configuration settings as a set
// of key-value pairs.
type ConfigData map[string]string

// ConfigManager defines methods for managing ConfigData.
type ConfigManager interface {
	EnsureDefault(ctx context.Context) error
	Read(ctx context.Context) (ConfigData, error)
	Delete(ctx context.Context) error
}

// GetDefaultConfig returns the default configuration data.
func GetDefaultConfig() ConfigData {
	return map[string]string{
		"trivy.severity":      "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"trivy.imageRef":      "docker.io/aquasec/trivy:0.9.1",
		"kube-bench.imageRef": "docker.io/aquasec/kube-bench:0.4.0",
		"polaris.config.yaml": polarisConfigYAML,
	}
}

func (c ConfigData) GetTrivyImageRef() string {
	if imageRef, ok := c["trivy.imageRef"]; ok {
		return imageRef
	}
	return "docker.io/aquasec/trivy:0.9.1"
}

// GetKubeBenchImageRef returns Docker image of kube-bench scanner.
func (c ConfigData) GetKubeBenchImageRef() string {
	if imageRef, ok := c["kube-bench.imageRef"]; ok {
		return imageRef
	}
	return "docker.io/aquasec/kube-bench:0.4.0"
}

// GetVersionFromImageRef returns the image identifier for the specified image reference.
func GetVersionFromImageRef(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parsing reference: %w", err)
	}

	var version string
	switch t := ref.(type) {
	case name.Tag:
		version = t.TagStr()
	case name.Digest:
		version = t.DigestStr()
	}

	return version, nil
}

// NewConfigManager constructs a new ConfigManager that is using kubernetes.Interface
// to manage ConfigData backed by the the ConfigMap stored in the specified namespace.
func NewConfigManager(client kubernetes.Interface, namespace string) ConfigManager {
	return &configManager{
		client:    client,
		namespace: namespace,
	}
}

type configManager struct {
	client    kubernetes.Interface
	namespace string
}

func (c *configManager) EnsureDefault(ctx context.Context) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      ConfigMapName,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
		},
		Data: GetDefaultConfig(),
	}
	_, err := c.client.CoreV1().ConfigMaps(c.namespace).Create(ctx, cm, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (c *configManager) Read(ctx context.Context) (ConfigData, error) {
	cm, err := c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return cm.Data, nil
}

func (c *configManager) Delete(ctx context.Context) error {
	err := c.client.CoreV1().ConfigMaps(c.namespace).Delete(ctx, ConfigMapName, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
