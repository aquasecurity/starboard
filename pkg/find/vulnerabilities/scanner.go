package vulnerabilities

import (
	"context"
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	core "k8s.io/api/core/v1"
)

type Scanner interface {
	Scan(ctx context.Context, workload kube.Workload) (reports map[string]sec.VulnerabilityReport, err error)
	ScanByPodSpec(ctx context.Context, workload kube.Workload, spec core.PodSpec) (reports map[string]sec.VulnerabilityReport, err error)
}
