package report

import (
	"fmt"
	"bytes"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type HTMLReporter struct {
	configAuditReport v1alpha1.ConfigAudit
	vulnerabilityReport v1alpha1.VulnerabilityReport
	savePath string
}

func NewHTMLReporter(configAuditReport v1alpha1.ConfigAudit, vulnerabilityReport v1alpha1.VulnerabilityReport, savePath string) HTMLReporter {
	return HTMLReporter{
		configAuditReport: configAuditReport,
		vulnerabilityReport: vulnerabilityReport,
		savePath: savePath,
	}
}

func (h *HTMLReporter) GenerateReport() (htmlReport interface{}, err error) {
	p := &templates.ReportPage{
		VulnsReport: h.vulnerabilityReport,
		ConfigAuditReport: h.configAuditReport,
		Workload: h.configAuditReport.Resource,
	}
	var buf bytes.Buffer
	templates.WritePageTemplate(&buf, p)
	fmt.Printf("\n%s", buf.Bytes())
	return nil, nil
}

func (h *HTMLReporter) PublishReport(htmlReport interface{}) (err error) {
	return nil
}
