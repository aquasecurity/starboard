package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewScanCmd(executable string, cf *genericclioptions.ConfigFlags) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:     "scan",
		Aliases: []string{"generate"},
		Short:   "Manage security weakness identification tools",
	}
	scanCmd.AddCommand(NewScanConfigAuditReportsCmd(cf))
	scanCmd.AddCommand(NewScanKubeBenchReportsCmd(cf))
	scanCmd.AddCommand(NewScanKubeHunterReportsCmd(cf))
	scanCmd.AddCommand(NewScanVulnerabilityReportsCmd(executable, cf))

	return scanCmd
}
