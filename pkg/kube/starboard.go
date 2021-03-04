package kube

import (
	"time"
)

const (
	// TODO I'm wondering if we should rename starboard.resource.* labels to starboard.object.*
	// TODO In Kubernetes API terminology a resource is usually lowercase, plural word (e.g. pods) identifying a set of
	// TODO HTTP endpoints (paths) exposing the CRUD semantics of a certain object type in the system
	LabelResourceKind      = "starboard.resource.kind"
	LabelResourceName      = "starboard.resource.name"
	LabelResourceNamespace = "starboard.resource.namespace"

	LabelContainerName    = "starboard.container.name"
	LabelPodSpecHash      = "pod-spec-hash"
	LabelPluginConfigHash = "plugin-config-hash"

	LabelConfigAuditReportScan   = "configAuditReport.scanner"
	LabelVulnerabilityReportScan = "vulnerabilityReport.scanner"
	LabelKubeBenchReportScan     = "kubeBenchReport.scanner"

	LabelK8SAppManagedBy = "app.kubernetes.io/managed-by"
	AppStarboardOperator = "starboard-operator"
)

const (
	AnnotationContainerImages = "starboard.container-images"
)

// ScannerOpts holds configuration of the vulnerability Scanner.
type ScannerOpts struct {
	ScanJobTimeout time.Duration
	DeleteScanJob  bool
}
