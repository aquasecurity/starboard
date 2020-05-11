package kubehunter

import (
	"encoding/json"
	"io"
	"time"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func OutputFrom(reader io.Reader) (report sec.KubeHunterOutput, err error) {
	report.GeneratedAt = meta.NewTime(time.Now())
	report.Scanner = sec.Scanner{
		Name:    "kube-hunter",
		Vendor:  "Aqua Security",
		Version: "latest",
	}
	err = json.NewDecoder(reader).Decode(&report)
	return
}
