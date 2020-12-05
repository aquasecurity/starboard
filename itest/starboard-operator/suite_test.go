package starboard_operator

import (
	"path/filepath"
	"testing"

	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/operator"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	buildInfo = starboard.BuildInfo{Version: "dev", Commit: "none", Date: "unknown"}
)

var (
	testEnv *envtest.Environment
)

var (
	kubernetesClientset kubernetes.Interface
	starboardClientset  starboardapi.Interface
)

func TestStarboardOperator(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Starboard Operator")
}

var _ = BeforeSuite(func(done Done) {
	operatorConfig, err := etc.GetOperatorConfig()
	Expect(err).ToNot(HaveOccurred())

	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	kubernetesConfig, err := ctrl.GetConfig()
	Expect(err).ToNot(HaveOccurred())

	kubernetesClientset, err = kubernetes.NewForConfig(kubernetesConfig)
	Expect(err).ToNot(HaveOccurred())

	starboardClientset, err = starboardapi.NewForConfig(kubernetesConfig)
	Expect(err).ToNot(HaveOccurred())

	testEnv = &envtest.Environment{
		UseExistingCluster: pointer.BoolPtr(true),
		Config:             kubernetesConfig,
		CRDDirectoryPaths:  []string{filepath.Join("..", "..", "deploy", "crd")},
	}

	_, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()

		err = operator.Run(buildInfo, operatorConfig)
		Expect(err).ToNot(HaveOccurred())
	}()

	close(done)
}, 60)

var _ = AfterSuite(func() {
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})
