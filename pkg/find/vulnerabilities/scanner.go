package vulnerabilities

import (
	"context"
	"github.com/aquasecurity/starboard/pkg/docker"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// WorkloadVulnerabilities holds VulnerabilityReports for each container
// of a Kubernetes workload.
type WorkloadVulnerabilities map[string]starboard.VulnerabilityReport

// ScannerAsync defines methods for a vulnerability scanner which is
// run as a Kubernetes Job.
//
// PrepareScanJob prepares a Job descriptor for the specified Kubernetes
// workload with the given Pod descriptor. The returned Job can be sent
// to the Kubernetes API and scheduled for execution.
//
// GetVulnerabilityReportsByScanJob returns WorkloadVulnerabilities from
// the completed scan Job.
type ScannerAsync interface {
	PrepareScanJob(ctx context.Context, workload kube.Object, spec corev1.PodSpec, auths map[string]docker.Auth) (*batchv1.Job, *corev1.Secret, error)
	GetVulnerabilityReportsByScanJob(ctx context.Context, job *batchv1.Job) (WorkloadVulnerabilities, error)
}

// Scanner defines methods for a synchronous vulnerability scanner.
// The implementations of the Scanner interface are supposed to block.
//
// Scan scans all container images of the specified Kubernetes workload.
// Returns a map of container names to VulnerabilityReports.
type Scanner interface {
	Scan(ctx context.Context, workload kube.Object) (WorkloadVulnerabilities, error)
}
