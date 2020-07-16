package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/report"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func generateHtmlReport(configaudit v1alpha1.ConfigAuditReport, vulnerabilities v1alpha1.Vulnerability) (err error, html string){
	fmt.Println("config: ", configaudit)
	fmt.Println("vulnerabilties: ", vulnerabilities)
	return nil, ""
}

func NewGetReportCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report (NAME | TYPE/NAME)",
		Short: "Generates a full html security report for a specified workload",
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
			starboardClientset, err := starboard.NewForConfig(config)
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

			// TODO: add selector latest to list options when it is implemented
			listOptions := v1.ListOptions{
				LabelSelector: fmt.Sprintf("starboard.resource.kind=%s,starboard.resource.name=%s", workload.Kind, workload.Name),
			}
			configAudits, err := starboardClientset.AquasecurityV1alpha1().ConfigAuditReports(workload.Namespace).List(ctx, listOptions)
			if err != nil {
				return
			}
			vulnsReports, err := starboardClientset.AquasecurityV1alpha1().Vulnerabilities(workload.Namespace).List(ctx, listOptions)
			if err != nil {
				return
			}

			if len(configAudits.Items) == 0 && len(vulnsReports.Items) == 0 {
				err = errors.New(fmt.Sprintf("No configaudits or vulnerabilities found for workload %s/%s/%s", workload.Namespace, workload.Kind, workload.Name))
				return
			}
			reporter := report.NewHTMLReporter(configAudits.Items, vulnsReports.Items, workload)
			htmlReport, err := reporter.GenerateReport()
			if err != nil {
				return
			}
			err = reporter.PublishReport(htmlReport)

			return
		},
	}

	return cmd
}


