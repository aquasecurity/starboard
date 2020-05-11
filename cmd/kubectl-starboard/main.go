package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/aquasecurity/starboard/pkg/cmd"
	"k8s.io/klog"
)

func main() {
	defer klog.Flush()

	initFlags()

	if err := cmd.GetRootCmd().Execute(); err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
}

func initFlags() {
	klog.InitFlags(nil)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	// Hide all klog flags except for -v
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name != "v" {
			pflag.Lookup(f.Name).Hidden = true
		}
	})
}
