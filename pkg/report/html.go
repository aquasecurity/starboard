package report

import (
	"bytes"
	"fmt"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type HTMLReporter struct {
	configAuditReports []starboard.ConfigAuditReport
	vulnerabilityReports []starboard.Vulnerability
	workload kube.Object
}

func NewHTMLReporter(configAuditReports []starboard.ConfigAuditReport, vulnerabilityReport []starboard.Vulnerability, workload kube.Object) HTMLReporter {
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
