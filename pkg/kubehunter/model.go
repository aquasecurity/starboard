package kubehunter

import (
	"encoding/json"
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"io"
)

func OutputFrom(reader io.Reader) (report sec.KubeHunterOutput, err error) {
	report.Scanner = sec.Scanner{
		Name:    "kube-hunter",
		Vendor:  "Aqua Security",
		Version: "latest",
	}
	err = json.NewDecoder(reader).Decode(&report)
	return
}
