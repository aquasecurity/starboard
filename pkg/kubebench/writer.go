package kubebench

import (
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Writer interface {
	Write(report sec.CISKubernetesBenchmarkReport, node string) error
}
