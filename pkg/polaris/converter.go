package polaris

import (
	"encoding/json"
	"io"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Converter interface {
	Convert(reader io.Reader) ([]sec.ConfigAudit, error)
}

type converter struct {
}

var DefaultConverter = NewConverter()

func NewConverter() Converter {
	return &converter{}
}

func (c *converter) Convert(reader io.Reader) (reports []sec.ConfigAudit, err error) {
	var report Report
	err = json.NewDecoder(reader).Decode(&report)
	if err != nil {
		return
	}
	reports = c.convert(report)
	return
}

func (c *converter) convert(report Report) (reports []sec.ConfigAudit) {
	reports = make([]sec.ConfigAudit, len(report.Results))
	for i, result := range report.Results {
		reports[i] = c.toConfigAudit(result)
	}
	return
}

func (c *converter) toConfigAudit(result Result) (report sec.ConfigAudit) {
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
			Vendor:  "Fairwinds",
			Version: "latest",
		},
		Resource: sec.KubernetesNamespacedResource{
			Namespace: result.Namespace,
			KubernetesResource: sec.KubernetesResource{
				Kind: result.Kind,
				Name: result.Name,
			},
		},
		PodChecks:       podChecks,
		ContainerChecks: containerChecks,
	}
	return
}
