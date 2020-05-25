package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/aquasecurity/starboard/pkg/cmd"
	"k8s.io/klog"
)

var (
	// These variables are populated by GoReleases via ldflags
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	defer klog.Flush()

	initFlags()

	version := cmd.VersionInfo{Version: version, Commit: commit, Date: date}

	if err := cmd.NewRootCmd(version).Execute(); err != nil {
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
