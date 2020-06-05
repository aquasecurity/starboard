package cmd

import (
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewRootCmd(version VersionInfo) *cobra.Command {
	var cf *genericclioptions.ConfigFlags

	rootCmd := &cobra.Command{
		Use:           "starboard",
		Short:         "Kubernetes-native security",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cf = genericclioptions.NewConfigFlags(true)

	rootCmd.AddCommand(NewVersionCmd(version))
	rootCmd.AddCommand(NewInitCmd(cf))
	rootCmd.AddCommand(NewRBACCmd(cf))
	rootCmd.AddCommand(NewFindCmd(cf))
	rootCmd.AddCommand(NewKubeBenchCmd(cf))
	rootCmd.AddCommand(NewKubeHunterCmd(cf))
	rootCmd.AddCommand(NewPolarisCmd(cf))
	rootCmd.AddCommand(NewGetCmd(cf))
	rootCmd.AddCommand(NewCleanupCmd(cf))

	SetGlobalFlags(cf, rootCmd)

	return rootCmd
}
