package itest

import (
	"os"
	"testing"

	"github.com/aquasecurity/starboard/pkg/cmd"

	"k8s.io/klog"

	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"

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
	starboardCLILogLevel = "0"
	versionInfo          = cmd.VersionInfo{Version: "dev", Commit: "none", Date: "unknown"}
)

var (
	namespaces                corev1.NamespaceInterface
	customResourceDefinitions apiextensions.CustomResourceDefinitionInterface
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

	klog.InitFlags(nil)

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
	customResourceDefinitions = apiextensionsClientset.CustomResourceDefinitions()
})

var _ = AfterSuite(func() {
	klog.Flush()
})
