package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	vulnsCrd "github.com/aquasecurity/starboard/pkg/find/vulnerabilities/crd"
	clientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	configAuditCrd "github.com/aquasecurity/starboard/pkg/polaris/crd"
	"github.com/aquasecurity/starboard/pkg/report"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewGetReportCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report (NAME | TYPE/NAME)",
		Short: "Get a full html security report for a specified workload",
		Long: `Generates a report that contains vulnerabilities and config audits found for the specified workload

TYPE is a Kubernetes workload. Shortcuts and API groups will be resolved, e.g. 'po' or 'deployments.apps'.
NAME is the name of a particular Kubernetes workload.			
`,
		Example: fmt.Sprintf(`  # Save report to a file
  %[1]s get report deploy/nginx > report.html`, "starboard"),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx := context.Background()
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			starboardClientset, err := clientset.NewForConfig(config)
			if err != nil {
				return
			}
			ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return
			}
			workload, err := WorkloadFromArgs(ns, args)
			if err != nil {
				return
			}

			caReader := configAuditCrd.NewReadWriter(starboardClientset)
			configAudit, err := caReader.Read(ctx, workload)
			if err != nil {
				return
			}

			vulnsReader := vulnsCrd.NewReadWriter(starboardClientset)
			vulnsReports, err := vulnsReader.Read(ctx, workload)
			if err != nil {
				return
			}

			// if no reports whatsoever
			if len(configAudit.Report.PodChecks) == 0 && len(vulnsReports) == 0 {
				err = errors.New((fmt.Sprintf("No configaudits or vulnerabilities found for workload %s/%s/%s", workload.Namespace, workload.Kind, workload.Name)))
				return
			}

			reporter := report.NewHTMLReporter(configAudit, vulnsReports, workload)
			err = reporter.GenerateReport(os.Stdout)

			return
		},
	}

	return cmd
}
