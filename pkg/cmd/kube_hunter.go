package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// Deprecated
// Use NewScanKubeHunterReportsCmd instead.
func NewKubeHunterCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:        "kube-hunter",
		Deprecated: "please use 'scan kubehunterreports' instead",
		Short:      kubeHunterCmdShort,
		RunE:       ScanKubeHunterReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}
