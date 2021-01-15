package main

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/operator"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
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

var (
	setupLog = log.Log.WithName("main")
)

// main is the entrypoint of the Starboard Operator executable command.
func main() {
	if err := run(); err != nil {
		setupLog.Error(err, "Unable to run starboard operator")
	}
}

func run() error {
	operatorConfig, err := etc.GetOperatorConfig()
	if err != nil {
		return fmt.Errorf("getting operator config: %w", err)
	}

	log.SetLogger(zap.New(zap.UseDevMode(operatorConfig.LogDevMode)))

	setupLog.Info("Starting operator", "buildInfo", buildInfo)

	return operator.Run(buildInfo, operatorConfig)
}
