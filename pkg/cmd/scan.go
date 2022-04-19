package cmd

import (
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"io"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewScanCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags, outWriter io.Writer) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:     "scan",
		Aliases: []string{"generate"},
		Short:   "Manage security weakness identification tools",
	}
	scanCmd.AddCommand(NewScanConfigAuditReportsCmd(buildInfo, cf))
	scanCmd.AddCommand(NewScanKubeBenchReportsCmd(cf))
	scanCmd.AddCommand(NewScanKubeHunterReportsCmd(cf))
	scanCmd.AddCommand(NewScanNamespaceCmd(buildInfo, cf, outWriter))
	scanCmd.AddCommand(NewScanVulnerabilityReportsCmd(buildInfo, cf))

	return scanCmd
}
