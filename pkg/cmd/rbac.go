package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewRBACCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rbac",
		Short: "Get RBAC config to run starboard",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			_, err = cf.ToRESTConfig()
			if err != nil {
				return
			}
			return
		},
	}
	return cmd
}
