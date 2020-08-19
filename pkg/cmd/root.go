package cmd

import (
	"flag"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewRootCmd(version VersionInfo, args []string, outWriter io.Writer, errWriter io.Writer) *cobra.Command {
	var cf *genericclioptions.ConfigFlags

	rootCmd := &cobra.Command{
		Use:           "starboard",
		Short:         "Kubernetes-native security toolkit",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cf = genericclioptions.NewConfigFlags(true)

	executable := executable(args)

	rootCmd.AddCommand(NewVersionCmd(version, outWriter, errWriter))
	rootCmd.AddCommand(NewInitCmd(cf))
	rootCmd.AddCommand(NewFindCmd(executable, cf))
	rootCmd.AddCommand(NewKubeBenchCmd(cf))
	rootCmd.AddCommand(NewKubeHunterCmd(cf))
	rootCmd.AddCommand(NewPolarisCmd(cf))
	rootCmd.AddCommand(NewGetCmd(executable, cf))
	rootCmd.AddCommand(NewCleanupCmd(cf))

	SetGlobalFlags(cf, rootCmd)

	rootCmd.SetArgs(args[1:])
	rootCmd.SetOut(outWriter)
	rootCmd.SetErr(errWriter)

	return rootCmd
}

func executable(args []string) string {
	if strings.HasPrefix(filepath.Base(args[0]), "kubectl-") {
		return "kubectl starboard"
	}
	return "starboard"
}

// Run is the entry point of the Starboard CLI. It runs the specified
// command based on the specified args.
func Run(version VersionInfo, args []string, outWriter io.Writer, errWriter io.Writer) error {

	initFlags()

	return NewRootCmd(version, args, outWriter, errWriter).Execute()
}

func initFlags() {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	// Hide all klog flags except for -v
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name != "v" {
			pflag.Lookup(f.Name).Hidden = true
		}
	})
}
