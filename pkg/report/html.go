package report

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"

	"github.com/aquasecurity/starboard/pkg/kube"
	configAuditCrd "github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type htmlReporter struct {
	vulnerabilityReportsReader vulnerabilityreport.ReadWriter
	configAuditReportsReader   configAuditCrd.ReadWriter
}

func NewHTMLReporter(configAuditReportsReader configAuditCrd.ReadWriter, vulnerabilityReportsReader vulnerabilityreport.ReadWriter) Reporter {
	return &htmlReporter{
		vulnerabilityReportsReader: vulnerabilityReportsReader,
		configAuditReportsReader:   configAuditReportsReader,
	}
}

func (h *htmlReporter) GenerateReport(workload kube.Object, writer io.Writer) error {
	ctx := context.Background()
	configAuditReport, err := h.configAuditReportsReader.FindByOwner(ctx, workload)
	if err != nil {
		return err
	}
	vulnerabilityReports, err := h.vulnerabilityReportsReader.FindByOwner(ctx, workload)
	if err != nil {
		return err
	}

	vulnsReports := map[string]v1alpha1.VulnerabilityScanResult{}
	for _, vulnerabilityReport := range vulnerabilityReports {
		containerName, ok := vulnerabilityReport.Labels[kube.LabelContainerName]
		if !ok {
			continue
		}
		vulnsReports[containerName] = vulnerabilityReport.Report
	}

	// if no reports whatsoever
	if configAuditReport == nil && len(vulnsReports) == 0 {
		return errors.New(fmt.Sprintf("No configaudits or vulnerabilities found for workload %s/%s/%s",
			workload.Namespace, workload.Kind, workload.Name))
	}

	p := &templates.ReportPage{
		VulnsReports:      vulnsReports,
		ConfigAuditReport: configAuditReport,
		Workload:          workload,
	}
	templates.WritePageTemplate(writer, p)
	return nil
}
