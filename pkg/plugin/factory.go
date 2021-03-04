package plugin

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/plugin/aqua"
	"github.com/aquasecurity/starboard/pkg/plugin/conftest"
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

// GetVulnerabilityPlugin is a factory method that instantiates the
// vulnerabilityreport.Plugin for the specified starboard.ConfigData.
//
// Starboard currently supports Trivy scanner in Standalone and ClientServer
// mode, and Aqua enterprise scanner.
//
// You could add your own scanner by implementing the
// vulnerabilityreport.Plugin interface.
func (r *Resolver) GetVulnerabilityPlugin() (vulnerabilityreport.Plugin, error) {
	scanner, err := r.config.GetVulnerabilityReportsScanner()
	if err != nil {
		return nil, err
	}
	switch scanner {
	case starboard.Trivy:
		return trivy.NewPlugin(ext.NewGoogleUUIDGenerator(), r.config), nil
	case starboard.Aqua:
		return aqua.NewPlugin(ext.NewGoogleUUIDGenerator(), r.buildInfo, r.config), nil
	}
	return nil, fmt.Errorf("unsupported vulnerability scanner plugin: %s", scanner)
}

// GetConfigAuditPlugin is a factory method that instantiates the
// configauditreport.Plugin for the specified starboard.ConfigData.
//
// Starboard supports Polaris as the only configuration auditing tool.
//
// You could add your own scanner by implementing the configauditreport.Plugin
// interface.
func (r *Resolver) GetConfigAuditPlugin() (configauditreport.Plugin, starboard.PluginContext, error) {
	scanner, err := r.config.GetConfigAuditReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := starboard.NewPluginContext().
		WithName(string(scanner)).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithClient(r.client).
		Build()

	switch scanner {
	case starboard.Polaris:
		return polaris.NewPlugin(ext.NewSystemClock(), r.config), pluginContext, nil
	case starboard.Conftest:
		return conftest.NewPlugin(ext.NewGoogleUUIDGenerator(), ext.NewSystemClock(), r.config), pluginContext, nil
	}
	return nil, nil, fmt.Errorf("unsupported configuration audit scanner plugin: %s", scanner)
}
