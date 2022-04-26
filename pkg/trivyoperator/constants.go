package trivyoperator

const (
	Banner = `Starboard is an Aqua Security open source project.
Learn about our open source work and portfolio on https://www.aquasec.com/products/open-source-projects/.
`
)

const (
	// NamespaceName the name of the namespace in which Starboard stores its
	// configuration and where it runs scan jobs.
	NamespaceName = "trivyoperator"

	// ServiceAccountName the name of the service account used to provide
	// identity for scan jobs run by Starboard.
	ServiceAccountName = "trivyoperator"

	// ConfigMapName the name of the ConfigMap where Starboard stores its
	// configuration.
	ConfigMapName = "trivyoperator"

	// SecretName the name of the secret where Starboard stores is sensitive
	// configuration.
	SecretName = "trivyoperator"

	// PoliciesConfigMapName the name of the ConfigMap used to store OPA Rego
	// policies.
	PoliciesConfigMapName = "trivyoperator-policies-config"
)

const (
	LabelResourceKind      = "trivyoperator.resource.kind"
	LabelResourceName      = "trivyoperator.resource.name"
	LabelResourceNameHash  = "trivyoperator.resource.name-hash"
	LabelResourceNamespace = "trivyoperator.resource.namespace"
	LabelContainerName     = "trivyoperator.container.name"
	LabelResourceSpecHash  = "resource-spec-hash"
	LabelPluginConfigHash  = "plugin-config-hash"

	LabelConfigAuditReportScanner   = "configAuditReport.scanner"
	LabelVulnerabilityReportScanner = "vulnerabilityReport.scanner"
	LabelKubeBenchReportScanner     = "kubeBenchReport.scanner"

	LabelK8SAppManagedBy = "app.kubernetes.io/managed-by"
	AppStarboard         = "trivyoperator"
)

const (
	AnnotationContainerImages = "trivyoperator.container-images"
)
