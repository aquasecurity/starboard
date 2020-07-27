package integration_tests

import (
	"os"
	"testing"

	"github.com/onsi/gomega/gexec"
	"k8s.io/client-go/tools/clientcmd"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
)

var (
	kubernetesClientset    kubernetes.Interface
	apiextensionsClientset apiextensions.ApiextensionsV1beta1Interface
)

var (
	pathToStarboardCLI string
)

var _ = BeforeSuite(func() {
	var err error
	pathToStarboardCLI, err = gexec.Build("github.com/aquasecurity/starboard/cmd/starboard")
	Expect(err).ToNot(HaveOccurred())

	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	Expect(err).ToNot(HaveOccurred())

	kubernetesClientset, err = kubernetes.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	apiextensionsClientset, err = apiextensions.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())
})

func TestStarboardCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Starboard CLI")
}

var _ = AfterSuite(func() {
	gexec.CleanupBuildArtifacts()
})
