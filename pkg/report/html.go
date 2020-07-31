package report

import (
	"bytes"
	"io"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type HTMLReporter struct {
	vulnerabilityReports vulnerabilities.WorkloadVulnerabilities
	configAuditReports   starboard.ConfigAuditReport
	workload             kube.Object
}

func NewHTMLReporter(configAuditReports starboard.ConfigAuditReport, vulnerabilityReport vulnerabilities.WorkloadVulnerabilities, workload kube.Object) HTMLReporter {
	return HTMLReporter{
		configAuditReports:   configAuditReports,
		vulnerabilityReports: vulnerabilityReport,
		workload:             workload,
	}
}

func (h *HTMLReporter) GenerateReport(writer io.Writer) (err error) {
	p := &templates.ReportPage{
		ConfigAuditReport: h.configAuditReports,
		VulnsReports:      h.vulnerabilityReports,
		Workload:          h.workload,
	}
	var buf bytes.Buffer
	templates.WritePageTemplate(&buf, p)
	writer.Write(buf.Bytes())
	return err
}
