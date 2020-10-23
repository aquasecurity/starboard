package kubehunter

import (
	"encoding/json"
	"io"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

func toSummary(vulnerabilities []sec.KubeHunterVulnerability) (summary sec.KubeHunterSummary) {
	for _, v := range vulnerabilities {
		switch v.Severity {
		case sec.KubeHunterSeverityHigh:
			summary.HighCount++
		case sec.KubeHunterSeverityMedium:
			summary.MediumCount++
		case sec.KubeHunterSeverityLow:
			summary.LowCount++
		default:
			summary.UnknownCount++
		}
	}
	return
}

func OutputFrom(reader io.Reader) (report sec.KubeHunterOutput, err error) {
	report.Scanner = sec.Scanner{
		Name:    "kube-hunter",
		Vendor:  "Aqua Security",
		Version: kubeHunterVersion,
	}
	err = json.NewDecoder(reader).Decode(&report)
	if err != nil {
		return
	}

	report.Summary = toSummary(report.Vulnerabilities)
	return
}
