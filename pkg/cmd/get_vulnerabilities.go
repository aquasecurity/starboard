package cmd

import (
	"fmt"
	"os/exec"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewGetVulnerabilitiesCmd(executable string, cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"vulns", "vuln"},
		Use:     "vulnerabilities (NAME | TYPE/NAME)",
		Short:   "Get vulnerabilities report",
		Long: `Get vulnerabilities report for the specified workload

TYPE is a Kubernetes workload. Shortcuts and API groups will be resolved, e.g. 'po' or 'deployments.apps'.
NAME is the name of a particular Kubernetes workload.
`,
		Example: fmt.Sprintf(`  # Get vulnerabilities for a Deployment with the specified name
  %[1]s get vulnerabilities.aquasecurity.github.io deploy/nginx

  # Get vulnerabilities for a Deployment with the specified name in the specified namespace
  %[1]s get vulnerabilities deploy/nginx -n staging

  # Get vulnerabilities for a ReplicaSet with the specified name
  %[1]s get vulns replicaset/nginx

  # Get vulnerabilities for a CronJob with the specified name in JSON output format
  %[1]s get vuln cj/my-job -o json`, executable),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return
			}
			workload, err := WorkloadFromArgs(ns, args)
			if err != nil {
				return
			}

			kubectlCmd := exec.Command("kubectl",
				"get",
				starboard.VulnerabilitiesCRName,
				fmt.Sprintf("-l=starboard.resource.kind=%s,starboard.resource.name=%s", workload.Kind, workload.Name),
				fmt.Sprintf("--namespace=%s", workload.Namespace),
				fmt.Sprintf("--output=%s", cmd.Flag("output").Value.String()))
			stdoutStderr, err := kubectlCmd.CombinedOutput()
			if err != nil {
				return
			}
			fmt.Printf("%s", stdoutStderr)
			return
		},
	}

	return cmd
}
