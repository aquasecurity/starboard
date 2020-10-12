package kubebench

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/starboard/pkg/starboard"

	aquasecurityv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Converter interface {
	Convert(config Config, reader io.Reader) (aquasecurityv1alpha1.CISKubeBenchOutput, error)
}

var DefaultConverter Converter = &converter{}

type converter struct {
}

func (c *converter) Convert(config Config, reader io.Reader) (report aquasecurityv1alpha1.CISKubeBenchOutput, err error) {
	decoder := json.NewDecoder(reader)
	var section []aquasecurityv1alpha1.CISKubeBenchSection
	err = decoder.Decode(&section)
	if err != nil {
		return
	}

	version, err := starboard.GetVersionFromImageRef(config.GetKubeBenchImageRef())
	if err != nil {
		return aquasecurityv1alpha1.CISKubeBenchOutput{}, err
	}

	report = aquasecurityv1alpha1.CISKubeBenchOutput{
		Scanner: aquasecurityv1alpha1.Scanner{
			Name:    "kube-bench",
			Vendor:  "Aqua Security",
			Version: version,
		},
		Summary:  c.summary(section),
		Sections: section,
	}

	return
}

func (c *converter) summary(sections []aquasecurityv1alpha1.CISKubeBenchSection) aquasecurityv1alpha1.CISKubeBenchSummary {
	totalPass := 0
	totalInfo := 0
	totalWarn := 0
	totalFail := 0

	for _, section := range sections {
		totalPass += section.TotalPass
		totalInfo += section.TotalInfo
		totalWarn += section.TotalWarn
		totalFail += section.TotalFail
	}

	return aquasecurityv1alpha1.CISKubeBenchSummary{
		PassCount: totalPass,
		InfoCount: totalInfo,
		WarnCount: totalWarn,
		FailCount: totalFail,
	}
}
