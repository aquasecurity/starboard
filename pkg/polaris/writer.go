package polaris

import (
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

// Write is the interface that wraps basic methods for persisting ConfigAudit reports.
//
// Write persists the given ConfigAudit report.
//
// WriteAll persists the given slice of ConfigAudit reports.
type Writer interface {
	Write(report sec.ConfigAudit) (err error)
	WriteAll(reports []sec.ConfigAudit) (err error)
}
