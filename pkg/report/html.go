package report

import (
	"bytes"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type HTMLReporter struct {
	configAuditReport v1alpha1.ConfigAuditReport
	vulnerabilityReports []v1alpha1.Vulnerability
	workload v1alpha1.KubernetesNamespacedResource
}

func NewHTMLReporter(configAuditReport v1alpha1.ConfigAuditReport, vulnerabilityReport []v1alpha1.Vulnerability, workload v1alpha1.KubernetesNamespacedResource) HTMLReporter {
	return HTMLReporter{
		configAuditReport: configAuditReport,
		vulnerabilityReports: vulnerabilityReport,
		workload: workload,
	}
}

func (h *HTMLReporter) GenerateReport() (htmlReport []byte, err error) {
	p := &templates.ReportPage{
		ConfigAuditReport: h.configAuditReport,
		VulnsReports: h.vulnerabilityReports,
		Workload: h.workload,
	}
	var buf bytes.Buffer
	templates.WritePageTemplate(&buf, p)
	return buf.Bytes(), nil
}

func (h *HTMLReporter) PublishReport(htmlReport []byte) (err error) {
	_, err = fmt.Printf("%s", htmlReport)
	return err
}
