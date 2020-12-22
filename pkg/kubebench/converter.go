package kubebench

import (
	"encoding/json"
	"io"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Converter interface {
	Convert(config Config, reader io.Reader) (v1alpha1.CISKubeBenchOutput, error)
}

var DefaultConverter Converter = &converter{}

type converter struct {
}

func (c *converter) Convert(config Config, reader io.Reader) (report v1alpha1.CISKubeBenchOutput, err error) {
	decoder := json.NewDecoder(reader)
	var section []v1alpha1.CISKubeBenchSection
	err = decoder.Decode(&section)
	if err != nil {
		return
	}

	imageRef, err := config.GetKubeBenchImageRef()
	if err != nil {
		return report, err
	}
	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.CISKubeBenchOutput{}, err
	}

	report = v1alpha1.CISKubeBenchOutput{
		Scanner: v1alpha1.Scanner{
			Name:    "kube-bench",
			Vendor:  "Aqua Security",
			Version: version,
		},
		Summary:         c.summary(section),
		UpdateTimestamp: metav1.NewTime(time.Now()),
		Sections:        section,
	}

	return
}

func (c *converter) summary(sections []v1alpha1.CISKubeBenchSection) v1alpha1.CISKubeBenchSummary {
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

	return v1alpha1.CISKubeBenchSummary{
		PassCount: totalPass,
		InfoCount: totalInfo,
		WarnCount: totalWarn,
		FailCount: totalFail,
	}
}
