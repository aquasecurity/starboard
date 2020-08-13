package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"

	"github.com/aquasecurity/starboard/pkg/cmd"
	"k8s.io/klog"

	// Load all known auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
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

	if err := cmd.NewRootCmd(executable(os.Args), version).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func executable(args []string) string {
	if strings.HasPrefix(filepath.Base(args[0]), "kubectl-") {
		return "kubectl starboard"
	}
	return "starboard"
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
