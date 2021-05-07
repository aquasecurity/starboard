package starboard_operator

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"context"

	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Starboard Operator", func() {

	// TODO Refactor to run this container in a separate test suite
	Describe("Vulnerability Scanner", VulnerabilityScannerBehavior(&inputs))

	// TODO Refactor to run this container in a separate test suite
	Describe("Configuration Checker", ConfigurationCheckerBehavior(&inputs))

	// TODO Refactor to run this container in a separate test suite
	Describe("CIS Kubernetes Benchmark", func() {

		Context("When operator is started", func() {

			It("Should create CISKubeBenchReports", func() {
				var nodeList corev1.NodeList
				err := kubeClient.List(context.Background(), &nodeList)
				Expect(err).ToNot(HaveOccurred())
				for _, node := range nodeList.Items {
					Eventually(inputs.HasCISKubeBenchReportOwnedBy(node), inputs.AssertTimeout).Should(BeTrue())
				}
			})

		})

	})

})
