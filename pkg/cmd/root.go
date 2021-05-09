package cmd

import (
	"flag"
	"io"

	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewRootCmd(buildInfo starboard.BuildInfo, args []string, outWriter io.Writer, errWriter io.Writer) *cobra.Command {
	var cf *genericclioptions.ConfigFlags

	rootCmd := &cobra.Command{
		Use:           "starboard",
		Short:         "Kubernetes-native security toolkit",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cf = genericclioptions.NewConfigFlags(true)

	rootCmd.AddCommand(NewVersionCmd(buildInfo, outWriter))
	rootCmd.AddCommand(NewInitCmd(cf))
	rootCmd.AddCommand(NewScanCmd(buildInfo, cf))
	rootCmd.AddCommand(NewGetCmd(buildInfo, cf, outWriter))
	rootCmd.AddCommand(NewCleanupCmd(cf))
	rootCmd.AddCommand(NewConfigCmd(cf, outWriter))

	SetGlobalFlags(cf, rootCmd)

	rootCmd.SetArgs(args[1:])
	rootCmd.SetOut(outWriter)
	rootCmd.SetErr(errWriter)

	return rootCmd
}

// Run is the entry point of the Starboard CLI. It runs the specified
// command based on the specified args.
func Run(version starboard.BuildInfo, args []string, outWriter io.Writer, errWriter io.Writer) error {

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
