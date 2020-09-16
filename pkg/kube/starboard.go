package kube

import (
	"time"
)

const (
	// NamespaceStarboard the name of the namespace in which Starboard stores its
	// configuration and runs scan Jobs.
	NamespaceStarboard = "starboard"
	// ServiceAccountStarboard the name of the ServiceAccount used to run scan Jobs.
	ServiceAccountStarboard = "starboard"
	// ConfigMapStarboard the name of the ConfigMap that stored configuration of
	// Starboard and the underlying scanners.
	ConfigMapStarboard = "starboard"
)

const (
	LabelResourceKind      = "aquasecurity.github.io/starboard-resource-kind"
	LabelResourceName      = "aquasecurity.github.io/starboard-resource-name"
	LabelResourceNamespace = "aquasecurity.github.io/starboard-resource-namespace"

	LabelContainerName = "aquasecurity.github.io/starboard-container-name"
)

const (
	AnnotationContainerImages = "aquasecurity.github.io/starboard-container-images"
)

// ScannerOpts holds configuration of the vulnerability Scanner.
type ScannerOpts struct {
	ScanJobTimeout time.Duration
	DeleteScanJob  bool
}
