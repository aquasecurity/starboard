package trivy

import (
	"encoding/json"
	"io"
	"time"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Converter is the interface that wraps the Convert method.
//
// Convert converts the vulnerabilities model used by Trivy
// to a generic model defined by K8S-native security CRDs.
type Converter interface {
	Convert(reader io.Reader) (sec.VulnerabilityReport, error)
}

type converter struct {
}

var DefaultConverter Converter = &converter{}

func (c *converter) Convert(reader io.Reader) (report sec.VulnerabilityReport, err error) {
	var scanReports []ScanReport
	err = json.NewDecoder(reader).Decode(&scanReports)
	if err != nil {
		return
	}
	report = c.convert(scanReports)
	return
}

func (c *converter) convert(reports []ScanReport) sec.VulnerabilityReport {
	var vulnerabilities []sec.VulnerabilityItem

	// TODO There might be > 1 item in the slice of reports (for app dependencies)
	for _, sr := range reports[0].Vulnerabilities {
		vulnerabilities = append(vulnerabilities, sec.VulnerabilityItem{
			VulnerabilityID:  sr.VulnerabilityID,
			Resource:         sr.PkgName,
			InstalledVersion: sr.InstalledVersion,
			FixedVersion:     sr.FixedVersion,
			Severity:         sr.Severity,
			LayerID:          sr.LayerID,
			Title:            sr.Title,
			Description:      sr.Description,
			Links:            c.toLinks(sr.References),
		})
	}

	return sec.VulnerabilityReport{
		GeneratedAt: meta.NewTime(time.Now()),
		Scanner: sec.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: "latest",
		},
		Summary:         c.toSummary(vulnerabilities),
		Vulnerabilities: vulnerabilities,
	}
}

func (c *converter) toLinks(references []string) []string {
	if references == nil {
		return []string{}
	}
	return references
}

func (c *converter) toSummary(vulnerabilities []sec.VulnerabilityItem) (vs sec.VulnerabilitySummary) {
	for _, v := range vulnerabilities {
		switch v.Severity {
		case sec.SeverityCritical:
			vs.CriticalCount++
		case sec.SeverityHigh:
			vs.HighCount++
		case sec.SeverityMedium:
			vs.MediumCount++
		case sec.SeverityLow:
			vs.LowCount++
		default:
			vs.UnknownCount++
		}
	}
	return
}
