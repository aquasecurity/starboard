package vulnerabilities

import (
	"context"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
)

type Writer interface {
	Write(ctx context.Context, workload kube.Workload, reports map[string]starboard.VulnerabilityReport) error
}
