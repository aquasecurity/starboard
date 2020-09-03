package cmd

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/crd"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/trivy"
	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func GetVulnerabilitiesCmd(executable string, cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"vulns", "vuln"},
		Use:     "vulnerabilities (NAME | TYPE/NAME)",
		Short:   "Scan a given workload for vulnerabilities using Trivy scanner",
		Long: `Scan a given workload for vulnerabilities using Trivy scanner

TYPE is a Kubernetes workload. Shortcuts and API groups will be resolved, e.g. 'po' or 'deployments.apps'.
NAME is the name of a particular Kubernetes workload.
`,
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
  %[1]s starboard find vulns daemonsets/nginx

  # Scan a statefulset with the specified name
  %[1]s vulns sts/redis

  # Scan a job with the specified name
  %[1]s find vulns job/my-job

  # Scan a cronjob with the specified name and the specified scan job timeout
  %[1]s find vulns cj/my-cronjob --scan-job-timeout 2m`, executable),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx := context.Background()
			ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return
			}
			mapper, err := cf.ToRESTMapper()
			if err != nil {
				return
			}
			workload, err := WorkloadFromArgs(mapper, ns, args)
			if err != nil {
				return
			}
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			kubernetesClientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return err
			}
			opts, err := getScannerOpts(cmd)
			if err != nil {
				return
			}
			reports, err := trivy.NewScanner(opts, kubernetesClientset).Scan(ctx, workload)
			if err != nil {
				return
			}
			starboardClientset, err := starboardapi.NewForConfig(config)
			if err != nil {
				return
			}
			err = crd.NewReadWriter(starboardClientset).Write(ctx, workload, reports)
			return
		},
	}

	registerScannerOpts(cmd)

	return cmd
}
