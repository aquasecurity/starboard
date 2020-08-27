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
		Sections: section,
	}

	return
}
