package ciskubebenchreport

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"context"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/itest/helper"
	"github.com/aquasecurity/starboard/pkg/operator"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
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

const (
	assertionTimeout = 3 * time.Minute
)

var (
	h *helper.Helper
)

func TestRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "CISKubeBenchReport Reconciler")
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

	h = helper.NewHelper(scheme, kubeClient)

	startCtx, stopFunc = context.WithCancel(context.Background())
	operatorConfig.CISKubernetesBenchmarkEnabled = true
	operatorConfig.VulnerabilityScannerEnabled = false
	operatorConfig.ConfigAuditScannerEnabled = false

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

	// TODO Delete CISKubeBenchReports
})
