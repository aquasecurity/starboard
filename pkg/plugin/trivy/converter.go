package trivy

import (
	"encoding/json"
	"io"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/google/go-containerregistry/pkg/name"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Converter is the interface that wraps the Convert method.
//
// Convert converts the vulnerabilities model used by Trivy
// to a generic model defined by the Custom Security Resource Specification.
type Converter interface {
	Convert(imageRef string, reader io.Reader) (v1alpha1.VulnerabilityScanResult, error)
}

type converter struct {
	config Config
}

func NewConverter(config Config) Converter {
	return &converter{
		config: config,
	}
}

func (c *converter) Convert(imageRef string, reader io.Reader) (v1alpha1.VulnerabilityScanResult, error) {
	var scanReports []ScanReport
	err := json.NewDecoder(reader).Decode(&scanReports)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}
	return c.convert(imageRef, scanReports)
}

func (c *converter) convert(imageRef string, reports []ScanReport) (v1alpha1.VulnerabilityScanResult, error) {
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)

	for _, report := range reports {
		for _, sr := range report.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, v1alpha1.Vulnerability{
				VulnerabilityID:  sr.VulnerabilityID,
				Resource:         sr.PkgName,
				InstalledVersion: sr.InstalledVersion,
				FixedVersion:     sr.FixedVersion,
				Severity:         sr.Severity,
				Title:            sr.Title,
				PrimaryLink:      sr.PrimaryURL,
				Links:            []string{},
				Score:            GetScoreFromCvss(sr.Cvss),
			})
		}
	}

	registry, artifact, err := c.parseImageRef(imageRef)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	trivyImageRef, err := c.config.GetTrivyImageRef()
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	version, err := starboard.GetVersionFromImageRef(trivyImageRef)
	if err != nil {
		return v1alpha1.VulnerabilityScanResult{}, err
	}

	return v1alpha1.VulnerabilityScanResult{
		UpdateTimestamp: metav1.NewTime(time.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: version,
		},
		Registry:        registry,
		Artifact:        artifact,
		Summary:         c.toSummary(vulnerabilities),
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (c *converter) toSummary(vulnerabilities []v1alpha1.Vulnerability) (vs v1alpha1.VulnerabilitySummary) {
	for _, v := range vulnerabilities {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			vs.CriticalCount++
		case v1alpha1.SeverityHigh:
			vs.HighCount++
		case v1alpha1.SeverityMedium:
			vs.MediumCount++
		case v1alpha1.SeverityLow:
			vs.LowCount++
		default:
			vs.UnknownCount++
		}
	}
	return
}

// TODO check if it works if both tag and digest are specified
func (c *converter) parseImageRef(imageRef string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return v1alpha1.Registry{}, v1alpha1.Artifact{}, err
	}
	registry := v1alpha1.Registry{
		Server: ref.Context().RegistryStr(),
	}
	artifact := v1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case name.Tag:
		artifact.Tag = t.TagStr()
	case name.Digest:
		artifact.Digest = t.DigestStr()
	}

	return registry, artifact, nil
}

func GetScoreFromCvss(CVSSs map[string]*CVSS) *float64 {
	var nvdScore, vendorScore *float64

	for name, cvss := range CVSSs {
		if name == "nvd" {
			nvdScore = cvss.V3Score
		} else {
			vendorScore = cvss.V3Score
		}
	}

	if vendorScore != nil {
		return vendorScore
	}

	return nvdScore
}
