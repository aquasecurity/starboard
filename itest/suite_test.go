package itest

import (
	"context"
	"os"
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	pathToStarboardCLI string
)

var _ = BeforeSuite(func() {
	var err error
	pathToStarboardCLI, err = Build("github.com/aquasecurity/starboard/cmd/starboard")
	Expect(err).ToNot(HaveOccurred())

	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	Expect(err).ToNot(HaveOccurred())

	kubernetesClientset, err = kubernetes.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	apiextensionsClientset, err = apiextensions.NewForConfig(config)
	Expect(err).ToNot(HaveOccurred())

	starboardClientset, err = starboardapi.NewForConfig(config)
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
	CleanupBuildArtifacts()
})

func GetNodeNames(ctx context.Context) ([]string, error) {
	nodesList, err := kubernetesClientset.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	names := make([]string, len(nodesList.Items))
	for i, node := range nodesList.Items {
		names[i] = node.Name
	}
	return names, nil
}
