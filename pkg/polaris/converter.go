package polaris

import (
	"encoding/json"
	"io"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Converter interface {
	Convert(reader io.Reader) (v1alpha1.ConfigAuditResult, error)
}

type converter struct {
	config Config
}

func NewConverter(config Config) Converter {
	return &converter{
		config: config,
	}
}

func (c *converter) Convert(reader io.Reader) (v1alpha1.ConfigAuditResult, error) {
	var report Report
	err := json.NewDecoder(reader).Decode(&report)
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}
	return c.toConfigAudit(report.Results[0])
}

// TODO Add success checks to the summary
func (c *converter) toSummary(podChecks []v1alpha1.Check, containerChecks map[string][]v1alpha1.Check) v1alpha1.ConfigAuditSummary {
	var summary v1alpha1.ConfigAuditSummary
	for _, c := range podChecks {
		if c.Success {
			continue
		}
		switch c.Severity {
		case v1alpha1.ConfigAuditDangerSeverity:
			summary.DangerCount++
		case v1alpha1.ConfigAuditWarningSeverity:
			summary.WarningCount++
		}
	}
	for _, checks := range containerChecks {
		for _, c := range checks {
			if c.Success {
				continue
			}
			switch c.Severity {
			case v1alpha1.ConfigAuditDangerSeverity:
				summary.DangerCount++
			case v1alpha1.ConfigAuditWarningSeverity:
				summary.WarningCount++
			}
		}
	}
	return summary
}

func (c *converter) toConfigAudit(result Result) (v1alpha1.ConfigAuditResult, error) {
	var podChecks []v1alpha1.Check
	containerChecks := make(map[string][]v1alpha1.Check)

	for _, pr := range result.PodResult.Results {
		podChecks = append(podChecks, v1alpha1.Check{
			ID:       pr.ID,
			Message:  pr.Message,
			Success:  pr.Success,
			Severity: pr.Severity,
			Category: pr.Category,
		})
	}

	for _, cr := range result.PodResult.ContainerResults {
		var checks []v1alpha1.Check
		for _, crr := range cr.Results {
			checks = append(checks, v1alpha1.Check{
				ID:       crr.ID,
				Message:  crr.Message,
				Success:  crr.Success,
				Severity: crr.Severity,
				Category: crr.Category,
			})

		}
		containerChecks[cr.Name] = checks
	}

	imageRef, err := c.config.GetPolarisImageRef()
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	return v1alpha1.ConfigAuditResult{
		Scanner: v1alpha1.Scanner{
			Name:    "Polaris",
			Vendor:  "Fairwinds Ops",
			Version: version,
		},
		Summary:         c.toSummary(podChecks, containerChecks),
		UpdateTimestamp: metav1.NewTime(time.Now()),
		PodChecks:       podChecks,
		ContainerChecks: containerChecks,
	}, nil
}
