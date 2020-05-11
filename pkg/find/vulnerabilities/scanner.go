package vulnerabilities

import (
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	core "k8s.io/api/core/v1"
)

type Scanner interface {
	Scan(workload kube.Workload) (reports map[string]sec.VulnerabilityReport, err error)
	ScanByPodSpec(workload kube.Workload, spec core.PodSpec) (reports map[string]sec.VulnerabilityReport, err error)
}
