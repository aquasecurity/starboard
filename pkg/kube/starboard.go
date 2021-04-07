package kube

import (
	"time"
)

// ScannerOpts holds configuration of the vulnerability Scanner.
type ScannerOpts struct {
	ScanJobTimeout time.Duration
	DeleteScanJob  bool
}
