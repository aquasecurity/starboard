package kubebench

import (
	"encoding/json"
	"io"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

func CISBenchmarkReportFrom(reader io.Reader) (report sec.CISKubernetesBenchmarkReport, err error) {
	decoder := json.NewDecoder(reader)
	report = sec.CISKubernetesBenchmarkReport{
		GeneratedAt: meta.NewTime(time.Now()),
		Scanner: sec.Scanner{
			Name:    "kube-bench",
			Vendor:  "Aqua Security",
			Version: "latest",
		},
		Sections: []sec.CISKubernetesBenchmarkSection{},
	}

	for {
		var section sec.CISKubernetesBenchmarkSection
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
