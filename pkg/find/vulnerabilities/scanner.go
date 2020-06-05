package vulnerabilities

import (
	"context"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	core "k8s.io/api/core/v1"
)

// Scanner defines methods for vulnerability scanner.
//
// Scan scans all container images of the specified Kubernetes workload.
// Returns a map of container names to VulnerabilityReports.
//
// ScanByPodSpec scans all container images of the specified Kubernetes workload with the given PodSpec.
// Returns a map of container names to VulnerabilityReports.
type Scanner interface {
	Scan(ctx context.Context, workload kube.Workload) (reports map[string]starboard.VulnerabilityReport, err error)
	ScanByPodSpec(ctx context.Context, workload kube.Workload, spec core.PodSpec) (reports map[string]starboard.VulnerabilityReport, err error)
}
