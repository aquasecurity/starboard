package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// Deprecated
// Use NewScanConfigAuditReportsCmd instead.
func NewPolarisCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:        "polaris",
		Deprecated: "please use 'scan configauditreports' instead",
		Short:      configAuditCmdShort,
		Args:       cobra.MaximumNArgs(1),
		RunE:       ScanConfigAuditReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}
