package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewGetCmd(executable string, cf *genericclioptions.ConfigFlags) *cobra.Command {
	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Get security reports",
	}
	getCmd.AddCommand(NewGetVulnerabilitiesCmd(executable, cf))
	getCmd.AddCommand(NewGetConfigAuditCmd(cf))
	getCmd.PersistentFlags().StringP("output", "o", "yaml", "Output format. One of yaml|json")

	return getCmd
}
