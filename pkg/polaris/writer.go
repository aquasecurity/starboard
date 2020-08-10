package polaris

import (
	"context"
	"github.com/aquasecurity/starboard/pkg/kube"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

// Write is the interface that wraps basic methods for persisting ConfigAudit reports.
//
// Write persists the given ConfigAudit report.
//
// WriteAll persists the given slice of ConfigAudit reports.
type Writer interface {
	Write(ctx context.Context, report sec.ConfigAudit) (err error)
	WriteAll(ctx context.Context, reports []sec.ConfigAudit) (err error)
}

// Reader is the interface that wraps basic methods for persistent reading of ConfigAudit reports.
//
// Read will return a single ConfigAuditReport that match a specific workload
type Reader interface {
	Read(ctx context.Context, workload kube.Object) (starboard.ConfigAuditReport, error)
}

type ReadWriter interface {
	Writer
	Reader
}
