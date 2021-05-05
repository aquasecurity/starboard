package ciskubebenchreport

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"context"

	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("CISKubeBenchReport Reconciler", func() {

	Context("When operator is started", func() {

		It("Should create CISKubeBenchReports", func() {
			var nodeList corev1.NodeList
			err := kubeClient.List(context.Background(), &nodeList)
			Expect(err).ToNot(HaveOccurred())
			for _, node := range nodeList.Items {
				Eventually(h.HasCISKubeBenchReportOwnedBy(node), assertionTimeout).Should(BeTrue())
			}
		})

	})

})
