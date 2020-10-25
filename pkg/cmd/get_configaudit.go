package cmd

import (
	"context"
	"fmt"
	"io"

	clientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewGetConfigAuditCmd(executable string, cf *genericclioptions.ConfigFlags, outWriter io.Writer) *cobra.Command {
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
  %[1]s get configaudit cj/my-job -o json`, executable),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx := context.Background()

			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			client, err := clientset.NewForConfig(config)
			if err != nil {
				return
			}

			ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return
			}
			mapper, err := cf.ToRESTMapper()
			if err != nil {
				return
			}
			workload, _, err := WorkloadFromArgs(mapper, ns, args)
			if err != nil {
				return
			}

			list, err := client.AquasecurityV1alpha1().
				ConfigAuditReports(workload.Namespace).
				List(ctx, metav1.ListOptions{
					LabelSelector: labels.Set{
						kube.LabelResourceKind:      string(workload.Kind),
						kube.LabelResourceName:      workload.Name,
						kube.LabelResourceNamespace: workload.Namespace,
					}.String(),
				})
			if err != nil {
				return fmt.Errorf("list config audit reports: %v", err)
			}

			format := cmd.Flag("output").Value.String()
			printer, err := genericclioptions.NewPrintFlags("").
				WithTypeSetter(GetScheme()).
				WithDefaultOutput(format).
				ToPrinter()
			if err != nil {
				return fmt.Errorf("create printer: %v", err)
			}

			if err := printer.PrintObj(list, outWriter); err != nil {
				return fmt.Errorf("print vulnerability reports: %v", err)
			}

			return nil
		},
	}

	return cmd
}
