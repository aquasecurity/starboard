package cmd

import (
	"io"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewGetCmd(executable string, cf *genericclioptions.ConfigFlags, outWriter io.Writer) *cobra.Command {
	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Get security reports",
	}
	getCmd.AddCommand(NewGetVulnerabilitiesCmd(executable, cf, outWriter))
	getCmd.AddCommand(NewGetConfigAuditCmd(executable, cf, outWriter))
	getCmd.AddCommand(NewGetReportCmd(cf))
	getCmd.PersistentFlags().StringP("output", "o", "yaml", "Output format. One of yaml|json")

	return getCmd
}
