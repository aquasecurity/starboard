package etc

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
)

type Config struct {
	Namespace               string        `env:"OPERATOR_NAMESPACE"`
	TargetNamespaces        string        `env:"OPERATOR_TARGET_NAMESPACES"`
	ServiceAccount          string        `env:"OPERATOR_SERVICE_ACCOUNT" envDefault:"starboard-operator"`
	ScanJobTimeout          time.Duration `env:"OPERATOR_SCAN_JOB_TIMEOUT" envDefault:"5m"`
	ConcurrentScanJobsLimit int           `env:"OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT" envDefault:"3"`
	ScanJobRetryAfter       time.Duration `env:"OPERATOR_SCAN_JOB_RETRY_AFTER" envDefault:"30s"`
	MetricsBindAddress      string        `env:"OPERATOR_METRICS_BIND_ADDRESS" envDefault:":8080"`
	HealthProbeBindAddress  string        `env:"OPERATOR_HEALTH_PROBE_BIND_ADDRESS" envDefault:":9090"`
	LogDevMode              bool          `env:"OPERATOR_LOG_DEV_MODE" envDefault:"false"`
}

func GetOperatorConfig() (Config, error) {
	var config Config
	err := env.Parse(&config)
	return config, err
}

// GetOperatorNamespace returns the namespace the operator should be running in.
func (c Config) GetOperatorNamespace() (string, error) {
	namespace := c.Namespace
	if namespace != "" {
		return namespace, nil
	}
	return "", fmt.Errorf("%s must be set", "OPERATOR_NAMESPACE")
}

// GetTargetNamespaces returns namespaces the operator should be watching for changes.
func (c Config) GetTargetNamespaces() []string {
	namespaces := c.TargetNamespaces
	if namespaces != "" {
		return strings.Split(namespaces, ",")
	}
	return []string{}
}

// InstallMode represents multitenancy support defined by the Operator Lifecycle Manager spec.
type InstallMode string

const (
	InstallModeOwnNamespace    InstallMode = "OwnNamespace"
	InstallModeSingleNamespace InstallMode = "SingleNamespace"
	InstallModeMultiNamespace  InstallMode = "MultiNamespace"
	InstallModeAllNamespaces   InstallMode = "AllNamespaces"
)

// GetInstallMode resolves InstallMode based on configured operator and target namespaces.
func (c Config) GetInstallMode() (InstallMode, error) {
	operatorNamespace, err := c.GetOperatorNamespace()
	if err != nil {
		return "", nil
	}
	targetNamespaces := c.GetTargetNamespaces()

	if len(targetNamespaces) == 1 && operatorNamespace == targetNamespaces[0] {
		return InstallModeOwnNamespace, nil
	}
	if len(targetNamespaces) == 1 && operatorNamespace != targetNamespaces[0] {
		return InstallModeSingleNamespace, nil
	}
	if len(targetNamespaces) > 1 {
		return InstallModeMultiNamespace, nil
	}
	return InstallModeAllNamespaces, nil
}
