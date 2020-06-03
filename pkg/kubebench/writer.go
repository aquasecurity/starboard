package kubebench

import (
	"context"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	core "k8s.io/api/core/v1"
)

type Writer interface {
	Write(ctx context.Context, report starboard.CISKubeBenchOutput, node *core.Node) error
}
