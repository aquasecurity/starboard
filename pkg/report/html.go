package report

import (
	"bytes"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type HTMLReporter struct {
	configAuditReport v1alpha1.ConfigAudit
	vulnerabilityReport v1alpha1.Vulnerability
	savePath string
}

func NewHTMLReporter(configAuditReport v1alpha1.ConfigAudit, vulnerabilityReport v1alpha1.Vulnerability, savePath string) HTMLReporter {
	return HTMLReporter{
		configAuditReport: configAuditReport,
		vulnerabilityReport: vulnerabilityReport,
		savePath: savePath,
	}
}

func (h *HTMLReporter) GenerateReport() (htmlReport []byte, err error) {
	p := &templates.ReportPage{
		Vulns: h.vulnerabilityReport,
		ConfigAuditReport: h.configAuditReport,
	}
	var buf bytes.Buffer
	templates.WritePageTemplate(&buf, p)
	return buf.Bytes(), nil
}

func (h *HTMLReporter) PublishReport(htmlReport []byte) (err error) {
	_, err = fmt.Printf("%s", htmlReport)
	return err
}
