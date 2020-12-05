package main

import (
	"fmt"
	"os"

	"github.com/aquasecurity/starboard/pkg/cmd"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"k8s.io/klog"

	// Load all known auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var (
	// These variables are populated by GoReleaser via ldflags
	version = "dev"
	commit  = "none"
	date    = "unknown"

	buildInfo = starboard.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
)

// main is the entrypoint of the Starboard CLI executable command.
func main() {
	defer klog.Flush()
	klog.InitFlags(nil)

	if err := cmd.Run(buildInfo, os.Args, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
