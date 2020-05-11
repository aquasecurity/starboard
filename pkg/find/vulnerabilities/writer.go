package vulnerabilities

import (
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
)

type Writer interface {
	Write(workload kube.Workload, reports map[string]sec.VulnerabilityReport) error
}
