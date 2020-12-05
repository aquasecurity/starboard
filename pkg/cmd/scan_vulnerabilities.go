package cmd

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"

	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"

	apis "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

const (
	vulnerabilitiesCmdShort = "Run static vulnerability scanner for each container image of a given workload"
	vulnerabilitiesCmdLong  = `Scan a given workload for vulnerabilities using Trivy scanner

TYPE is a Kubernetes workload. Shortcuts and API groups will be resolved, e.g. 'po' or 'deployments.apps'.
NAME is the name of a particular Kubernetes workload.
`
)

func NewScanVulnerabilityReportsCmd(executable string, cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"vulns", "vuln"},
		Use:     "vulnerabilityreports (NAME | TYPE/NAME)",
		Short:   vulnerabilitiesCmdShort,
		Long:    vulnerabilitiesCmdShort,
		Example: fmt.Sprintf(`  # Scan a pod with the specified name
  %[1]s scan vulnerabilities nginx

  # Scan a pod with the specified name in the specified namespace
  %[1]s scan vulnerabilityreports po/nginx -n staging

  # Scan a replicaset with the specified name
  %[1]s scan vulnerabilityreports replicaset/nginx

  # Scan a replicationcontroller with the given name
  %[1]s scan vulnerabilityreports rc/nginx

  # Scan a deployment with the specified name
  %[1]s scan vulnerabilityreports deployments.apps/nginx

  # Scan a daemonset with the specified name
  %[1]s scan vulnerabilityreports daemonsets/nginx

  # Scan a statefulset with the specified name
  %[1]s vulnerabilityreports sts/redis

  # Scan a job with the specified name
  %[1]s scan vulnerabilityreports job/my-job

  # Scan a cronjob with the specified name and the specified scan job timeout
  %[1]s scan vulnerabilityreports cj/my-cronjob --scan-job-timeout 2m`, executable),
		RunE: ScanVulnerabilityReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}

func ScanVulnerabilityReports(cf *genericclioptions.ConfigFlags) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
		if err != nil {
			return err
		}
		mapper, err := cf.ToRESTMapper()
		if err != nil {
			return err
		}
		workload, _, err := WorkloadFromArgs(mapper, ns, args)
		if err != nil {
			return err
		}
		kubernetesConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		kubernetesClientset, err := kubernetes.NewForConfig(kubernetesConfig)
		if err != nil {
			return err
		}
		config, err := starboard.NewConfigManager(kubernetesClientset, starboard.NamespaceName).Read(ctx)
		if err != nil {
			return err
		}
		opts, err := getScannerOpts(cmd)
		if err != nil {
			return err
		}
		reports, err := vulnerabilities.NewScanner(starboard.NewScheme(), kubernetesClientset, config, opts).Scan(ctx, workload)
		if err != nil {
			return err
		}
		starboardClientset, err := apis.NewForConfig(kubernetesConfig)
		if err != nil {
			return err
		}
		return vulnerabilityreport.NewReadWriter(starboardClientset).Write(ctx, reports)
	}
}
