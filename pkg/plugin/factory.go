package plugin

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/plugin/aqua"
	"github.com/aquasecurity/starboard/pkg/plugin/polaris"
	"github.com/aquasecurity/starboard/pkg/plugin/trivy"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Resolver struct {
	buildInfo          starboard.BuildInfo
	config             starboard.ConfigData
	namespace          string
	serviceAccountName string
	client             client.Client
}

func NewResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) WithBuildInfo(buildInfo starboard.BuildInfo) *Resolver {
	r.buildInfo = buildInfo
	return r
}

func (r *Resolver) WithConfig(config starboard.ConfigData) *Resolver {
	r.config = config
	return r
}

func (r *Resolver) WithNamespace(namespace string) *Resolver {
	r.namespace = namespace
	return r
}

func (r *Resolver) WithServiceAccountName(name string) *Resolver {
	r.serviceAccountName = name
	return r
}

func (r *Resolver) WithClient(client client.Client) *Resolver {
	r.client = client
	return r
}

func (r *Resolver) GetVulnerabilityPlugin() (vulnerabilityreport.Plugin, error) {
	return GetVulnerabilityReportPlugin(r.buildInfo, r.config)
}

func (r *Resolver) GetConfigAuditPlugin() (configauditreport.Plugin, starboard.PluginContext, error) {
	return polaris.NewPlugin(ext.NewSystemClock(), r.config), starboard.NewPluginContext().
			WithName("Polaris").
			WithNamespace(r.namespace).
			WithServiceAccountName(r.serviceAccountName).
			WithClient(r.client).
			Build(),
		nil
}

// GetVulnerabilityReportPlugin is a factory method that instantiates the
// vulnerabilityreport.Plugin for the specified starboard.ConfigData.
//
// Starboard currently supports Trivy scanner in Standalone and ClientServer
// mode, and Aqua enterprise scanner.
//
// You could add your own scanner by implementing the
// vulnerabilityreport.Plugin interface.
// Deprecated
func GetVulnerabilityReportPlugin(buildInfo starboard.BuildInfo, config starboard.ConfigData) (vulnerabilityreport.Plugin, error) {
	scanner, err := config.GetVulnerabilityReportsScanner()
	if err != nil {
		return nil, err
	}
	switch scanner {
	case starboard.Trivy:
		return trivy.NewPlugin(ext.NewGoogleUUIDGenerator(), config), nil
	case starboard.Aqua:
		return aqua.NewPlugin(ext.NewGoogleUUIDGenerator(), buildInfo, config), nil
	}
	return nil, fmt.Errorf("unsupported vulnerability scanner plugin: %s", scanner)
}

// GetConfigAuditReportPlugin is a factory method that instantiates the
// configauditreport.Plugin for the specified starboard.ConfigData.
//
// Starboard supports Polaris as the only configuration auditing tool.
//
// You could add your own scanner by implementing the configauditreport.Plugin
// interface.
// Deprecated
func GetConfigAuditReportPlugin(_ starboard.BuildInfo, config starboard.ConfigData) (configauditreport.Plugin, error) {
	return polaris.NewPlugin(ext.NewSystemClock(), config), nil
}
