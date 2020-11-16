package polaris

import (
	"encoding/json"
	"io"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Converter interface {
	Convert(reader io.Reader) (sec.ConfigAuditResult, error)
}

type converter struct {
}

var DefaultConverter = NewConverter()

func NewConverter() Converter {
	return &converter{}
}

func (c *converter) Convert(reader io.Reader) (reports sec.ConfigAuditResult, err error) {
	var report Report
	err = json.NewDecoder(reader).Decode(&report)
	if err != nil {
		return
	}
	reports = c.toConfigAudit(report.Results[0])
	return
}

func (c *converter) toSummary(podChecks []sec.Check, containerChecks map[string][]sec.Check) (summary sec.ConfigAuditSummary) {
	for _, c := range podChecks {
		if c.Success {
			continue
		}
		switch c.Severity {
		case sec.ConfigAuditDangerSeverity:
			summary.DangerCount++
		case sec.ConfigAuditWarningSeverity:
			summary.WarningCount++
		}
	}
	for _, checks := range containerChecks {
		for _, c := range checks {
			if c.Success {
				continue
			}
			switch c.Severity {
			case sec.ConfigAuditDangerSeverity:
				summary.DangerCount++
			case sec.ConfigAuditWarningSeverity:
				summary.WarningCount++
			}
		}
	}
	return
}

func (c *converter) toConfigAudit(result Result) (report sec.ConfigAuditResult) {
	var podChecks []sec.Check
	containerChecks := make(map[string][]sec.Check)

	for _, pr := range result.PodResult.Results {
		podChecks = append(podChecks, sec.Check{
			ID:       pr.ID,
			Message:  pr.Message,
			Success:  pr.Success,
			Severity: pr.Severity,
			Category: pr.Category,
		})
	}

	for _, cr := range result.PodResult.ContainerResults {
		var checks []sec.Check
		for _, crr := range cr.Results {
			checks = append(checks, sec.Check{
				ID:       crr.ID,
				Message:  crr.Message,
				Success:  crr.Success,
				Severity: crr.Severity,
				Category: crr.Category,
			})

		}
		containerChecks[cr.Name] = checks
	}

	report = sec.ConfigAuditResult{
		Scanner: sec.Scanner{
			Name:    "Polaris",
			Vendor:  "Fairwinds Ops",
			Version: polarisVersion,
		},
		Summary:         c.toSummary(podChecks, containerChecks),
		UpdateTimestamp: metav1.NewTime(time.Now()),
		PodChecks:       podChecks,
		ContainerChecks: containerChecks,
	}
	return
}
