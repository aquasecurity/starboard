package starboard

const (
	// NamespaceName the name of the namespace in which Starboard stores its
	// configuration and runs scan Jobs.
	NamespaceName = "starboard"

	// ServiceAccountName the name of the ServiceAccount used to run scan Jobs.
	ServiceAccountName = "starboard"

	// ConfigMapName the name of the ConfigMap that stored configuration of
	// Starboard and the underlying scanners.
	ConfigMapName = "starboard"
)
