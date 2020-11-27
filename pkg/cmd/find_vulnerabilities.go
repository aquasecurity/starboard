package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// Deprecated
// Use NewScanVulnerabilityReportsCmd instead.
func NewFindVulnerabilitiesCmd(executable string, cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Aliases:    []string{"vulns", "vuln"},
		Use:        "vulnerabilities (NAME | TYPE/NAME)",
		Deprecated: "please use 'scan vulnerabilityreports' instead",
		Short:      vulnerabilitiesCmdShort,
		Long:       vulnerabilitiesCmdLong,
		Example: fmt.Sprintf(`  # Scan a pod with the specified name
  %[1]s find vulnerabilities nginx

  # Scan a pod with the specified name in the specified namespace
  %[1]s find vulns po/nginx -n staging

  # Scan a replicaset with the specified name
  %[1]s find vuln replicaset/nginx

  # Scan a replicationcontroller with the given name
  %[1]s find vulns rc/nginx

  # Scan a deployment with the specified name
  %[1]s find vulns deployments.apps/nginx

  # Scan a daemonset with the specified name
  %[1]s find vulns daemonsets/nginx

  # Scan a statefulset with the specified name
  %[1]s vulns sts/redis

  # Scan a job with the specified name
  %[1]s find vulns job/my-job

  # Scan a cronjob with the specified name and the specified scan job timeout
  %[1]s find vulns cj/my-cronjob --scan-job-timeout 2m`, executable),
		RunE: ScanVulnerabilityReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}
