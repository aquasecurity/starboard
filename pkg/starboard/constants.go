package starboard

const (
	Banner = `Starboard is an Aqua Security open source project.
Learn about our open source work and portfolio on https://www.aquasec.com/products/open-source-projects/.
`
)

const (
	// NamespaceName the name of the namespace in which Starboard stores its
	// configuration and where it runs scan jobs.
	NamespaceName = "starboard"

	// ServiceAccountName the name of the service account used to provide
	// identity for scan jobs run by Starboard.
	ServiceAccountName = "starboard"

	// ConfigMapName the name of the ConfigMap where Starboard stores its
	// configuration.
	ConfigMapName = "starboard"

	// SecretName the name of the secret where Starboard stores is sensitive
	// configuration.
	SecretName = "starboard"

	// PoliciesConfigMapName the name of the ConfigMap used to store OPA Rego
	// policies.
	PoliciesConfigMapName = "starboard-policies-config"
)

const (
	LabelResourceKind      = "starboard.resource.kind"
	LabelResourceName      = "starboard.resource.name"
	LabelResourceNameHash  = "starboard.resource.name-hash"
	LabelResourceNamespace = "starboard.resource.namespace"
	LabelContainerName     = "starboard.container.name"
	LabelResourceSpecHash  = "resource-spec-hash"
	LabelPluginConfigHash  = "plugin-config-hash"

	LabelConfigAuditReportScanner   = "configAuditReport.scanner"
	LabelVulnerabilityReportScanner = "vulnerabilityReport.scanner"
	LabelKubeBenchReportScanner     = "kubeBenchReport.scanner"

	LabelK8SAppManagedBy = "app.kubernetes.io/managed-by"
	AppStarboard         = "starboard"
)

const (
	AnnotationContainerImages = "starboard.container-images"
)
