package cmd

import (
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewFindCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) *cobra.Command {
	findCmd := &cobra.Command{
		Use:   "find",
		Short: "Manage security scanners",
	}
	findCmd.AddCommand(NewFindVulnerabilitiesCmd(buildInfo, cf))

	return findCmd
}
