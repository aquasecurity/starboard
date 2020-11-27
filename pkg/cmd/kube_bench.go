package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// Deprecated
// Use NewScanKubeBenchReportsCmd instead.
func NewKubeBenchCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:        "kube-bench",
		Deprecated: "please use 'scan ciskubebenchreports' instead",
		Short:      kubeBenchCmdShort,
		RunE:       ScanKubeBenchReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}
