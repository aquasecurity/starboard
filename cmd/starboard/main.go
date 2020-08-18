package main

import (
	"fmt"
	"os"

	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/cmd"

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
	klog.InitFlags(nil)

	version := cmd.VersionInfo{Version: version, Commit: commit, Date: date}
	if err := cmd.Run(version, os.Args, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
