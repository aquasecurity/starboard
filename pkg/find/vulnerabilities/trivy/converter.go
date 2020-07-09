package trivy

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"strings"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
)

// Converter is the interface that wraps the Convert method.
//
// Convert converts the vulnerabilities model used by Trivy
// to a generic model defined by the Custom Security Resource Specification.
type Converter interface {
	Convert(imageRef string, reader io.Reader) (starboard.VulnerabilityReport, error)
}

type converter struct {
}

var DefaultConverter = NewConverter()

func NewConverter() Converter {
	return &converter{}
}

func (c *converter) Convert(imageRef string, reader io.Reader) (report starboard.VulnerabilityReport, err error) {
	var scanReports []ScanReport
	skipReader, err := c.skippingNoisyOutputReader(reader)
	if err != nil {
		return
	}
	err = json.NewDecoder(skipReader).Decode(&scanReports)
	if err != nil {
		return
	}
	return c.convert(imageRef, scanReports)
}

// TODO Normally I'd use Trivy with the --quiet flag, but in case of errors it does suppress the error message.
// TODO Therefore, as a workaround I do sanitize the input reader before we start parsing the JSON output.
func (c *converter) skippingNoisyOutputReader(input io.Reader) (io.Reader, error) {
	inputAsBytes, err := ioutil.ReadAll(input)
	if err != nil {
		return nil, err
	}
	inputAsString := string(inputAsBytes)

	index := strings.Index(inputAsString, "\n[")
	if index > 0 {
		return strings.NewReader(inputAsString[index:]), nil
	}
	index = strings.LastIndex(inputAsString, "null")
	if index > 0 {
		return strings.NewReader(inputAsString[index:]), nil
	}
	return strings.NewReader(inputAsString), nil
}

func (c *converter) convert(imageRef string, reports []ScanReport) (starboard.VulnerabilityReport, error) {
	vulnerabilities := make([]starboard.VulnerabilityItem, 0)

	for _, report := range reports {
		for _, sr := range report.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, starboard.VulnerabilityItem{
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
	}

	registry, artifact, err := c.parseImageRef(imageRef)
	if err != nil {
		return starboard.VulnerabilityReport{}, err
	}

	return starboard.VulnerabilityReport{
		Scanner: starboard.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: trivyVersion,
		},
		Registry:        registry,
		Artifact:        artifact,
		Summary:         c.toSummary(vulnerabilities),
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (c *converter) toLinks(references []string) []string {
	if references == nil {
		return []string{}
	}
	return references
}

func (c *converter) toSummary(vulnerabilities []starboard.VulnerabilityItem) (vs starboard.VulnerabilitySummary) {
	for _, v := range vulnerabilities {
		switch v.Severity {
		case starboard.SeverityCritical:
			vs.CriticalCount++
		case starboard.SeverityHigh:
			vs.HighCount++
		case starboard.SeverityMedium:
			vs.MediumCount++
		case starboard.SeverityLow:
			vs.LowCount++
		default:
			vs.UnknownCount++
		}
	}
	return
}

func (c *converter) parseImageRef(imageRef string) (starboard.Registry, starboard.Artifact, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return starboard.Registry{}, starboard.Artifact{}, err
	}
	registry := starboard.Registry{
		URL: ref.Context().RegistryStr(),
	}
	artifact := starboard.Artifact{
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
