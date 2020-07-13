package cmd

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/spf13/cobra"
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
		Short: "Generate full HTML report for a given workload",
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
			configAudit, err := starboardClientset.AquasecurityV1alpha1().ConfigAuditReports(workload.Namespace).List(ctx, listOptions)
			if err != nil {
				return
			}
			vulnsReport, err := starboardClientset.AquasecurityV1alpha1().Vulnerabilities(workload.Namespace).List(ctx, listOptions)
			if err != nil {
				return
			}

			if err, _ := generateHtmlReport(configAudit.Items[0], vulnsReport.Items[0]); err != nil {

			}
			return
		},
	}

	return cmd
}


