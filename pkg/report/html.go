package report

import (
	"bytes"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/report/templates"
	"github.com/aquasecurity/starboard/pkg/kube"
)

type HTMLReporter struct {
	configAuditReports []v1alpha1.ConfigAuditReport
	vulnerabilityReports []v1alpha1.Vulnerability
	workload kube.Object
}

func NewHTMLReporter(configAuditReports []v1alpha1.ConfigAuditReport, vulnerabilityReport []v1alpha1.Vulnerability, workload kube.Object) HTMLReporter {
	return HTMLReporter{
		configAuditReports: configAuditReports,
		vulnerabilityReports: vulnerabilityReport,
		workload: workload,
	}
}

func (h *HTMLReporter) GenerateReport() (htmlReport []byte, err error) {
	p := &templates.ReportPage{
		ConfigAuditReports: h.configAuditReports,
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
