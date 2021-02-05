package kubebench

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/starboard"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Converter struct {
	ext.Clock
	Config
}

func (c *Converter) Convert(reader io.Reader) (v1alpha1.CISKubeBenchOutput, error) {
	output := &struct {
		Controls []v1alpha1.CISKubeBenchSection `json:"Controls"`
	}{}

	decoder := json.NewDecoder(reader)
	err := decoder.Decode(output)
	if err != nil {
		return v1alpha1.CISKubeBenchOutput{}, err
	}

	imageRef, err := c.Config.GetKubeBenchImageRef()
	if err != nil {
		return v1alpha1.CISKubeBenchOutput{}, err
	}
	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.CISKubeBenchOutput{}, err
	}

	return v1alpha1.CISKubeBenchOutput{
		Scanner: v1alpha1.Scanner{
			Name:    "kube-bench",
			Vendor:  "Aqua Security",
			Version: version,
		},
		Summary:         c.summary(output.Controls),
		UpdateTimestamp: metav1.NewTime(c.Clock.Now()),
		Sections:        output.Controls,
	}, nil
}

func (c *Converter) summary(sections []v1alpha1.CISKubeBenchSection) v1alpha1.CISKubeBenchSummary {
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
