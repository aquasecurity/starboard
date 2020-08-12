package kubebench

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/kube"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	core "k8s.io/api/core/v1"
)

type Writer interface {
	Write(ctx context.Context, report starboard.CISKubeBenchOutput, node *core.Node) error
}

type Reader interface {
	Read(ctx context.Context, node kube.Object) (starboard.CISKubeBenchOutput, error)
}

type ReadWriter interface {
	Writer
	Reader
}
