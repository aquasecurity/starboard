package cmd

import (
	"flag"
	"io"
	"path/filepath"
	"strings"

	starboardv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewRootCmd(version starboard.BuildInfo, args []string, outWriter io.Writer, errWriter io.Writer) *cobra.Command {
	var cf *genericclioptions.ConfigFlags

	rootCmd := &cobra.Command{
		Use:           "starboard",
		Short:         "Kubernetes-native security toolkit",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cf = genericclioptions.NewConfigFlags(true)

	executable := executable(args)

	rootCmd.AddCommand(NewVersionCmd(version, outWriter))
	rootCmd.AddCommand(NewInitCmd(cf))
	rootCmd.AddCommand(NewFindCmd(executable, cf))
	rootCmd.AddCommand(NewKubeBenchCmd(cf))
	rootCmd.AddCommand(NewKubeHunterCmd(cf))
	rootCmd.AddCommand(NewPolarisCmd(cf))
	rootCmd.AddCommand(NewGetCmd(executable, cf, outWriter))
	rootCmd.AddCommand(NewCleanupCmd(cf))
	rootCmd.AddCommand(NewConfigCmd(cf, outWriter))

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

func init() {
	_ = starboardv1alpha1.AddToScheme(GetScheme())
}
