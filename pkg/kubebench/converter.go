package kubebench

import (
	"encoding/json"
	"io"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Converter interface {
	Convert(reader io.Reader) (report starboard.CISKubeBenchOutput, err error)
}

var DefaultConverter Converter = &converter{}

type converter struct {
}

func (c *converter) Convert(reader io.Reader) (report starboard.CISKubeBenchOutput, err error) {
	decoder := json.NewDecoder(reader)
	var section []starboard.CISKubeBenchSection
	err = decoder.Decode(&section)
	if err != nil {
		return
	}

	report = starboard.CISKubeBenchOutput{
		Scanner: starboard.Scanner{
			Name:    "kube-bench",
			Vendor:  "Aqua Security",
			Version: kubeBenchVersion,
		},
		Summary:  c.summary(section),
		Sections: section,
	}

	return
}

func (c *converter) summary(sections []starboard.CISKubeBenchSection) starboard.CISKubeBenchSummary {
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

	return starboard.CISKubeBenchSummary{
		PassCount: totalPass,
		InfoCount: totalInfo,
		WarnCount: totalWarn,
		FailCount: totalFail,
	}
}
