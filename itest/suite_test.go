package itest

import (
	"os"
	"testing"

	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned/typed/aquasecurity/v1alpha1"

	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"

	. "github.com/onsi/gomega/gexec"
	"k8s.io/client-go/tools/clientcmd"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
)

var (
	kubernetesClientset    kubernetes.Interface
	apiextensionsClientset apiextensions.ApiextensionsV1beta1Interface
	starboardClientset     starboardapi.Interface
)

var (
	pathToStarboardCLI   string
	starboardCLILogLevel = "0"
)

var (
	namespaces                corev1.NamespaceInterface
	customResourceDefinitions apiextensions.CustomResourceDefinitionInterface
	defaultPods               corev1.PodInterface
	defaultDeployments        appsv1.DeploymentInterface
	defaultVulnerabilities    v1alpha1.VulnerabilityInterface
)

// TestStarboardCLI is a spec that describes the behavior of Starboard CLI.
func TestStarboardCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Starboard CLI")
}

var _ = BeforeSuite(func() {
	var err error
	pathToStarboardCLI, err = Build("github.com/aquasecurity/starboard/cmd/starboard")
	Expect(err).ToNot(HaveOccurred())

	if logLevel, ok := os.LookupEnv("STARBOARD_CLI_LOG_LEVEL"); ok {
		starboardCLILogLevel = logLevel
	}

	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	Expect(err).ToNot(HaveOccurred())

	kubernetesClientset, err = kubernetes.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	apiextensionsClientset, err = apiextensions.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	starboardClientset, err = starboardapi.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	namespaces = kubernetesClientset.CoreV1().Namespaces()
	defaultPods = kubernetesClientset.CoreV1().Pods(metav1.NamespaceDefault)
	defaultDeployments = kubernetesClientset.AppsV1().Deployments(metav1.NamespaceDefault)
	customResourceDefinitions = apiextensionsClientset.CustomResourceDefinitions()
	defaultVulnerabilities = starboardClientset.AquasecurityV1alpha1().Vulnerabilities(metav1.NamespaceDefault)
})

var _ = AfterSuite(func() {
	CleanupBuildArtifacts()
})
