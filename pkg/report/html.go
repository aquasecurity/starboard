package report

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"

	vulnsCrd "github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube"
	configAuditCrd "github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type HTMLReporter struct {
	vulnerabilityReportsReader vulnsCrd.ReadWriter
	configAuditReportsReader   configAuditCrd.ReadWriter
	workload                   kube.Object
}

func NewHTMLReporter(configAuditReportsReader configAuditCrd.ReadWriter, vulnerabilityReportsReader vulnsCrd.ReadWriter, workload kube.Object) HTMLReporter {
	return HTMLReporter{
		vulnerabilityReportsReader: vulnerabilityReportsReader,
		configAuditReportsReader:   configAuditReportsReader,
		workload:                   workload,
	}
}

func (h *HTMLReporter) readVulnerabilitiesAndConfigAudits() (vulnsReports vulnerabilities.WorkloadVulnerabilities, configAudit v1alpha1.ConfigAuditReport, err error) {
	ctx := context.Background()
	configAudit, err = h.configAuditReportsReader.Read(ctx, h.workload)
	if err != nil {
		return
	}
	vulnsReports, err = h.vulnerabilityReportsReader.Read(ctx, h.workload)
	if err != nil {
		return
	}

	// if no reports whatsoever
	if len(configAudit.Report.PodChecks) == 0 && len(vulnsReports) == 0 {
		err = errors.New(fmt.Sprintf("No configaudits or vulnerabilities found for workload %s/%s/%s", h.workload.Namespace, h.workload.Kind, h.workload.Name))
	}
	return
}

func (h *HTMLReporter) GenerateReport(writer io.Writer) (err error) {
	vulnsReport, configAudit, err := h.readVulnerabilitiesAndConfigAudits()
	if err != nil {
		return
	}

	p := &templates.ReportPage{
		VulnsReports:      vulnsReport,
		ConfigAuditReport: configAudit,
		Workload:          h.workload,
	}

	templates.WritePageTemplate(writer, p)
	return nil
}
