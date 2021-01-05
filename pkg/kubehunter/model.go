package kubehunter

import (
	"encoding/json"
	"io"
	"time"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func OutputFrom(config Config, reader io.Reader) (report sec.KubeHunterOutput, err error) {
	imageRef, err := config.GetKubeHunterImageRef()
	if err != nil {
		return report, err
	}
	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return sec.KubeHunterOutput{}, err
	}

	report.Scanner = sec.Scanner{
		Name:    "kube-hunter",
		Vendor:  "Aqua Security",
		Version: version,
	}
	report.UpdateTimestamp = metav1.NewTime(time.Now())
	err = json.NewDecoder(reader).Decode(&report)
	if err != nil {
		return
	}

	report.Summary = toSummary(report.Vulnerabilities)
	return
}
