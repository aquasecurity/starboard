package kubebench

import (
	"encoding/json"
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"io"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Converter interface {
	Convert(reader io.Reader) (report starboard.CISKubernetesBenchmarkReport, err error)
}

var DefaultConverter Converter = &converter{
	clock: ext.NewSystemClock(),
}

type converter struct {
	clock ext.Clock
}

func (c *converter) Convert(reader io.Reader) (report starboard.CISKubernetesBenchmarkReport, err error) {
	decoder := json.NewDecoder(reader)
	report = starboard.CISKubernetesBenchmarkReport{
		GeneratedAt: meta.NewTime(c.clock.Now()),
		Scanner: starboard.Scanner{
			Name:    "kube-bench",
			Vendor:  "Aqua Security",
			Version: "latest",
		},
		Sections: []starboard.CISKubernetesBenchmarkSection{},
	}

	for {
		var section starboard.CISKubernetesBenchmarkSection
		de := decoder.Decode(&section)
		if de == io.EOF {
			break
		}
		if de != nil {
			err = de
			break
		}
		report.Sections = append(report.Sections, section)
	}
	return
}
