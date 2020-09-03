package cmd

import (
	"fmt"
	"os/exec"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewGetConfigAuditCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configaudit (NAME | TYPE/NAME)",
		Short: "Get configuration audit report",
		Long: `Get configuration audit report for the specified workload

TYPE is a Kubernetes workload. Shortcuts and API groups will be resolved, e.g. 'po' or 'deployments.apps'.
NAME is the name of a particular Kubernetes workload.
`,
		Example: fmt.Sprintf(`  # Get configuration audit for a Deployment with the specified name
  %[1]s get configauditreports.aquasecurity.github.io deploy/nginx

  # Get configuration audit for a Deployment with the specified name in the specified namespace
  %[1]s get configauditreports deploy/nginx -n staging

  # Get configuration audit for a ReplicaSet with the specified name
  %[1]s get configaudit replicaset/nginx

  # Get vulnerabilities for a CronJob with the specified name in JSON output format
  %[1]s get configaudit cj/my-job -o json`, "starboard"),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
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

			kubectlCmd := exec.Command("kubectl",
				"get",
				starboard.ConfigAuditReportCRName,
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
