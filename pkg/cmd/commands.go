package cmd

import (
	"errors"
	"strings"
	"time"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func SetGlobalFlags(cf *genericclioptions.ConfigFlags, cmd *cobra.Command) {
	cf.AddFlags(cmd.Flags())
	for _, c := range cmd.Commands() {
		SetGlobalFlags(cf, c)
	}
}

func WorkloadFromArgs(namespace string, args []string) (workload kube.Workload, err error) {
	if len(args) < 1 {
		err = errors.New("required workload kind and name not specified")
		return
	}

	parts := strings.SplitN(args[0], "/", 2)
	if len(parts) == 1 {
		workload = kube.Workload{
			Namespace: namespace,
			Kind:      kube.WorkloadKindPod,
			Name:      parts[0],
		}
		return
	}
	kind, err := kube.WorkloadKindFromString(parts[0])
	if err != nil {
		return
	}
	if "" == parts[1] {
		err = errors.New("required workload name is blank")
		return
	}
	workload = kube.Workload{
		Namespace: namespace,
		Kind:      kind,
		Name:      parts[1],
	}
	return
}

const (
	scanJobTimeoutFlagName = "scan-job-timeout"
)

func registerScannerOpts(cmd *cobra.Command) {
	cmd.Flags().Duration(scanJobTimeoutFlagName, time.Duration(0),
		"The length of time to wait before giving up on a scan job. Non-zero values should contain a"+
			" corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout the scan job.")

}

func getScannerOpts(cmd *cobra.Command) (opts kube.ScannerOpts, err error) {
	opts.ScanJobTimeout, err = cmd.Flags().GetDuration(scanJobTimeoutFlagName)
	if err != nil {
		return
	}
	return
}
