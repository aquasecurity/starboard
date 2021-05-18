package etc

const (
	// NamespaceName the name of the namespace in which Starboard-operator stores its
	// configuration and where it runs scan jobs.
	NamespaceName = "starboard-operator"

	// ServiceAccountName the name of the service account used to provide
	// identity for scan jobs run by Starboard-operator.
	ServiceAccountName = "starboard-operator"

	// ConfigMapName the name of the ConfigMap where Starboard-operator stores its
	// configuration.
	ConfigMapName = "starboard"

	// SecretName the name of the secret where Starboard-operator stores is sensitive
	// configuration.
	SecretName = "starboard-operator"
)

const (
	AnnotationCustomAnnotationsForScanJobPods = "starboard-operator.custom-annotations"
)
