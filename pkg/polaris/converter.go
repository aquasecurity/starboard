package polaris

import (
	"encoding/json"
	"io"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
)

type Converter interface {
	Convert(config starboard.Config, reader io.Reader) (sec.ConfigAudit, error)
}

type converter struct {
}

var DefaultConverter = NewConverter()

func NewConverter() Converter {
	return &converter{}
}

func (c *converter) Convert(config starboard.Config, reader io.Reader) (reports sec.ConfigAudit, err error) {
	var report Report
	err = json.NewDecoder(reader).Decode(&report)
	if err != nil {
		return
	}
	version, err := starboard.GetVersionFromImageRef(config.GetImageRef(starboard.PolarisImageRef))
	if err != nil {
		return sec.ConfigAudit{}, err
	}

	reports = c.toConfigAudit(version, report.Results[0])
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

func (c *converter) toConfigAudit(polarisVersion string, result Result) (report sec.ConfigAudit) {
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

	report = sec.ConfigAudit{
		Scanner: sec.Scanner{
			Name:    "Polaris",
			Vendor:  "Fairwinds Ops",
			Version: polarisVersion,
		},
		Summary:         c.toSummary(podChecks, containerChecks),
		PodChecks:       podChecks,
		ContainerChecks: containerChecks,
	}
	return
}
