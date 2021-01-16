package config

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/aqua"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/trivy"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
)

// GetVulnerabilityReportPlugin is a factory method that instantiates the
// vulnerabilityreport.Plugin for the specified starboard.ConfigData.
//
// Starboard currently supports Trivy scanner in Standalone and ClientServer
// mode, and Aqua enterprise scanner.
//
// You could add your own scanner by implementing the
// vulnerabilityreport.Plugin interface.
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
