package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewFindCmd(executable string, cf *genericclioptions.ConfigFlags) *cobra.Command {
	findCmd := &cobra.Command{
		Use:   "find",
		Short: "Manage security scanners",
	}
	findCmd.AddCommand(NewFindVulnerabilitiesCmd(executable, cf))

	return findCmd
}
