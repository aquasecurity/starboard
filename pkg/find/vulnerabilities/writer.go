package vulnerabilities

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/kube"
)

type Writer interface {
	Write(ctx context.Context, workload kube.Object, reports WorkloadVulnerabilities) error
}

type Reader interface {
	Read(ctx context.Context, workload kube.Object) (WorkloadVulnerabilities, error)
}

type ReadWriter interface {
	Reader
	Writer
}
