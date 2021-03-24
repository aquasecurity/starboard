package starboard

import (
	"context"
	"os"
	"testing"

	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/starboard"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apicorev1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const namespaceItest = "starboard-itest"

var (
	scheme                 *runtime.Scheme
	kubeClient             client.Client
	kubernetesClientset    kubernetes.Interface
	apiextensionsClientset apiextensions.ApiextensionsV1beta1Interface
	starboardClientset     starboardapi.Interface
)

var (
	starboardCLILogLevel = "0"
	versionInfo          = starboard.BuildInfo{Version: "dev", Commit: "none", Date: "unknown"}
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

	scheme = starboard.NewScheme()
	kubeClient, err = client.New(config, client.Options{Scheme: scheme})
	Expect(err).ToNot(HaveOccurred())

	kubernetesClientset, err = kubernetes.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	apiextensionsClientset, err = apiextensions.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	starboardClientset, err = starboardapi.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	namespaces = kubernetesClientset.CoreV1().Namespaces()
	customResourceDefinitions = apiextensionsClientset.CustomResourceDefinitions()

	err = createNamespace()
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	err := deleteNamespace()
	Expect(err).ToNot(HaveOccurred())
	klog.Flush()
})

func createNamespace() error {
	_, err := kubernetesClientset.CoreV1().Namespaces().Create(context.TODO(), &apicorev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: namespaceItest,
	}}, metav1.CreateOptions{})
	return err
}

func deleteNamespace() error {
	err := kubernetesClientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceItest, metav1.DeleteOptions{})
	return err
}
