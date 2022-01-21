package conftest

import (
	_ "embed"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"context"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/itest/helper"
	"github.com/aquasecurity/starboard/itest/starboard-operator/behavior"
	"github.com/aquasecurity/starboard/pkg/operator"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/plugin/conftest"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	buildInfo = starboard.BuildInfo{
		Version: "dev",
		Commit:  "none",
		Date:    "unknown",
	}
)

var (
	scheme     *runtime.Scheme
	kubeClient client.Client
	startCtx   context.Context
	stopFunc   context.CancelFunc
)

var (
	inputs behavior.Inputs
)

var (
	starboardCM *corev1.ConfigMap
	conftestCM  *corev1.ConfigMap

	//go:embed testdata/run_as_root.rego
	runAsRootPolicy string
	//go:embed testdata/service_with_external_ip.rego
	serviceWithExternalIPPolicy string
)

func TestIntegrationOperatorWithConftest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Conftest")
}

var _ = BeforeSuite(func() {
	operatorConfig, err := etc.GetOperatorConfig()
	Expect(err).ToNot(HaveOccurred())

	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(operatorConfig.LogDevMode)))

	kubeConfig, err := ctrl.GetConfig()
	Expect(err).ToNot(HaveOccurred())

	scheme = starboard.NewScheme()
	kubeClient, err = client.New(kubeConfig, client.Options{
		Scheme: scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	inputs = behavior.Inputs{
		AssertTimeout:         3 * time.Minute,
		PrimaryNamespace:      corev1.NamespaceDefault,
		PrimaryWorkloadPrefix: "wordpress",

		ConfigAuditReportsPlugin: conftest.Plugin,

		Client: kubeClient,
		Helper: helper.NewHelper(kubeClient),
	}

	// We can disable vulnerability scanner and CIS benchmarks
	operatorConfig.VulnerabilityScannerEnabled = false
	operatorConfig.CISKubernetesBenchmarkEnabled = false

	starboardCM = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorConfig.Namespace,
			Name:      starboard.ConfigMapName,
		},
		Data: map[string]string{
			"configAuditReports.scanner": "Conftest",
			"conftest.imageRef":          "docker.io/openpolicyagent/conftest:v0.28.2",
		},
	}
	err = kubeClient.Create(context.Background(), starboardCM)
	Expect(err).ToNot(HaveOccurred())

	conftestCM = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorConfig.Namespace,
			Name:      starboard.GetPluginConfigMapName("Conftest"),
		},
		Data: map[string]string{
			"conftest.imageRef": "docker.io/openpolicyagent/conftest:v0.28.2",

			"conftest.policy.runs_as_root.rego":              runAsRootPolicy,
			"conftest.policy.runs_as_root.kinds":             "Workload",
			"conftest.policy.service_with_external_ip.rego":  serviceWithExternalIPPolicy,
			"conftest.policy.service_with_external_ip.kinds": "Service",
		},
	}
	err = kubeClient.Create(context.Background(), conftestCM)
	Expect(err).ToNot(HaveOccurred())

	startCtx, stopFunc = context.WithCancel(context.Background())

	go func() {
		defer GinkgoRecover()
		By("Starting Starboard operator")
		err = operator.Start(startCtx, buildInfo, operatorConfig)
		Expect(err).ToNot(HaveOccurred())
	}()

})

var _ = AfterSuite(func() {
	By("Stopping Starboard operator")
	stopFunc()
	err := kubeClient.Delete(context.Background(), starboardCM)
	Expect(err).ToNot(HaveOccurred())
	err = kubeClient.Delete(context.Background(), conftestCM)
	Expect(err).ToNot(HaveOccurred())
})
