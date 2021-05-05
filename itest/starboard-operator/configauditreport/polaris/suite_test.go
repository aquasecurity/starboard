package polaris

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"context"
	"testing"

	"github.com/aquasecurity/starboard/itest/helper"
	"github.com/aquasecurity/starboard/itest/starboard-operator/configauditreport"
	"github.com/aquasecurity/starboard/pkg/operator"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
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
	inputs configauditreport.SharedBehaviorInputs
)

var (
	starboardCM *corev1.ConfigMap
	polarisCM   *corev1.ConfigMap
)

func TestRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "ConfigAuditReport Reconciler - Polaris")
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

	inputs = configauditreport.SharedBehaviorInputs{
		Client: kubeClient,
		Helper: helper.NewHelper(scheme, kubeClient),
	}

	startCtx, stopFunc = context.WithCancel(context.Background())
	operatorConfig.ConfigAuditScannerEnabled = true
	operatorConfig.CISKubernetesBenchmarkEnabled = false
	operatorConfig.VulnerabilityScannerEnabled = false

	starboardCM = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorConfig.Namespace,
			Name:      starboard.ConfigMapName,
		},
		Data: map[string]string{
			"configAuditReports.scanner": "Polaris",
			"polaris.imageRef":           "quay.io/fairwinds/polaris:3.2",
		},
	}
	err = kubeClient.Create(context.Background(), starboardCM)
	Expect(err).ToNot(HaveOccurred())

	polarisCM = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorConfig.Namespace,
			Name:      starboard.GetPluginConfigMapName("Polaris"),
		},
		Data: map[string]string{
			"polaris.config.yaml": `checks:
  runAsRootAllowed: danger
`,
		},
	}
	err = kubeClient.Create(context.Background(), polarisCM)
	Expect(err).ToNot(HaveOccurred())

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
	err = kubeClient.Delete(context.Background(), polarisCM)
	Expect(err).ToNot(HaveOccurred())
})
