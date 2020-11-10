package starboard

import (
  "os"
)

func getEnv(key, fallback string) string {
    value, exists := os.LookupEnv(key)
    if !exists {
        value = fallback
    }
    return value
}

// NamespaceName the name of the namespace in which Starboard stores its
// configuration and runs scan Jobs.
var NamespaceName = getEnv("STARBOARD_CONFIG_NAMESPACE", "starboard")

// ServiceAccountName the name of the ServiceAccount used to run scan Jobs.
var	ServiceAccountName = getEnv("STARBOARD_SA_NAME", "starboard")

// ConfigMapName the name of the ConfigMap that stored configuration of
// Starboard and the underlying scanners.
var ConfigMapName = getEnv("STARBOARD_CONFIGMAP_NAME", "starboard")
