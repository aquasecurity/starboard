package etc

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
)

type Config struct {
	Namespace                     string        `env:"OPERATOR_NAMESPACE"`
	TargetNamespaces              string        `env:"OPERATOR_TARGET_NAMESPACES"`
	ServiceAccount                string        `env:"OPERATOR_SERVICE_ACCOUNT" envDefault:"starboard-operator"`
	ScanJobTimeout                time.Duration `env:"OPERATOR_SCAN_JOB_TIMEOUT" envDefault:"5m"`
	ConcurrentScanJobsLimit       int           `env:"OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT" envDefault:"10"`
	ScanJobRetryAfter             time.Duration `env:"OPERATOR_SCAN_JOB_RETRY_AFTER" envDefault:"30s"`
	MetricsBindAddress            string        `env:"OPERATOR_METRICS_BIND_ADDRESS" envDefault:":8080"`
	HealthProbeBindAddress        string        `env:"OPERATOR_HEALTH_PROBE_BIND_ADDRESS" envDefault:":9090"`
	LogDevMode                    bool          `env:"OPERATOR_LOG_DEV_MODE" envDefault:"false"`
	CISKubernetesBenchmarkEnabled bool          `env:"OPERATOR_CIS_KUBERNETES_BENCHMARK_ENABLED" envDefault:"true"`
	VulnerabilityScannerEnabled   bool          `env:"OPERATOR_VULNERABILITY_SCANNER_ENABLED" envDefault:"true"`
	ConfigAuditScannerEnabled     bool          `env:"OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED" envDefault:"true"`
	LeaderElectionEnabled         bool          `env:"OPERATOR_LEADER_ELECTION_ENABLED" envDefault:"false"`
	LeaderElectionID              string        `env:"OPERATOR_LEADER_ELECTION_ID" envDefault:"starboard-operator"`
	BatchDeleteLimit              int           `env:"OPERATOR_BATCH_DELETE_LIMIT" envDefault:"10"`
	BatchDeleteDelay              time.Duration `env:"OPERATOR_BATCH_DELETE_DELAY" envDefault:"10s"`
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
	OwnNamespace    InstallMode = "OwnNamespace"
	SingleNamespace InstallMode = "SingleNamespace"
	MultiNamespace  InstallMode = "MultiNamespace"
	AllNamespaces   InstallMode = "AllNamespaces"
)

// ResolveInstallMode resolves InstallMode based on configured Config.Namespace and Config.TargetNamespaces.
func (c Config) ResolveInstallMode() (InstallMode, string, []string, error) {
	operatorNamespace, err := c.GetOperatorNamespace()
	if err != nil {
		return "", "", nil, err
	}
	targetNamespaces := c.GetTargetNamespaces()

	if len(targetNamespaces) == 1 && operatorNamespace == targetNamespaces[0] {
		return OwnNamespace, operatorNamespace, targetNamespaces, nil
	}
	if len(targetNamespaces) == 1 && operatorNamespace != targetNamespaces[0] {
		return SingleNamespace, operatorNamespace, targetNamespaces, nil
	}
	if len(targetNamespaces) > 1 {
		return MultiNamespace, operatorNamespace, targetNamespaces, nil
	}
	return AllNamespaces, operatorNamespace, targetNamespaces, nil
}
