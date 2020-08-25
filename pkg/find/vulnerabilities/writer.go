package vulnerabilities

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/starboard/pkg/kube"
)

type Writer interface {
	Write(ctx context.Context, reports WorkloadVulnerabilities, owner metav1.Object) error
}

type Reader interface {
	Read(ctx context.Context, workload kube.Object) (WorkloadVulnerabilities, error)
}

type ReadWriter interface {
	Reader
	Writer
}
