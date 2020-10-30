package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/aquasecurity/starboard/pkg/polaris/crd"

	clientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/spf13/cobra"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			config, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			client, err := clientset.NewForConfig(config)
			if err != nil {
				return err
			}

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
			scheme := starboard.NewScheme()
			report, err := crd.NewReadWriter(scheme, client).FindByOwner(ctx, workload)
			if err != nil {
				return nil
			}

			if report == nil {
				fmt.Fprintf(outWriter, "No reports found in %s namespace.\n", workload.Namespace)
				return nil
			}

			format := cmd.Flag("output").Value.String()
			printer, err := genericclioptions.NewPrintFlags("").
				WithTypeSetter(scheme).
				WithDefaultOutput(format).
				ToPrinter()
			if err != nil {
				return fmt.Errorf("create printer: %v", err)
			}

			if err := printer.PrintObj(report, outWriter); err != nil {
				return fmt.Errorf("print vulnerability reports: %v", err)
			}

			return nil
		},
	}

	return cmd
}
