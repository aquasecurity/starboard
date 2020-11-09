package main

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/operator"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// GoReleaser sets three ldflags:
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	buildInfo = starboard.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
)

var (
	setupLog = log.Log.WithName("main")
)

func main() {
	if err := run(); err != nil {
		setupLog.Error(err, "Unable to run manager")
	}
}

func run() error {
	operatorConfig, err := etc.GetOperatorConfig()
	if err != nil {
		return fmt.Errorf("getting operator config: %w", err)
	}

	log.SetLogger(zap.New(zap.UseDevMode(operatorConfig.Operator.LogDevMode)))

	setupLog.Info("Starting operator", "buildInfo", buildInfo)

	return operator.Run(buildInfo, operatorConfig)
}
