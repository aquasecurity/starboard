package cmd

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/plugin"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"github.com/spf13/cobra"
	"io"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/printers"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sync"
)

const (
	namespaceCmdShort = "Run a variety of checks to ensure that a given workload is configured using best practices and has no vulnerabilities"
)

func NewScanNamespaceCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace",
		Short: namespaceCmdShort,
		Args:  cobra.MaximumNArgs(1),
		RunE:  ScanNamespace(buildInfo, cf, out),
	}
	cmd.PersistentFlags().StringP("output", "o", "", "Output format. One of yaml|json")

	registerScannerOpts(cmd)

	return cmd
}

func ScanNamespace(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags, outWriter io.Writer) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		kubeConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		dynaClient, err := dynamic.NewForConfig(kubeConfig)
		if err != nil {
			return err
		}
		namespace, err := getNamespaceFromArg(args)
		if err != nil {
			return err
		}
		scheme := starboard.NewScheme()
		// scan for config audit
		kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
		allResources, err := getResources(ctx, dynaClient, namespace, getNamespaceGVR())
		if err != nil {
			return err
		}
		var wg sync.WaitGroup
		wg.Add(2)
		scanErr := make(chan error, 2)
		configReportChan := make(chan *v1alpha1.ConfigAuditReportList, 1)
		// scan config audit for misconfiguration
		go func(scanErr chan error, configReportChan chan *v1alpha1.ConfigAuditReportList) {
			defer wg.Done()
			scanner := configauditreport.NewScanner(buildInfo, kubeClient)
			list := &v1alpha1.ConfigAuditReportList{
				Items: []v1alpha1.ConfigAuditReport{},
			}
			for _, resource := range allResources {
				reportBuilder, err := scanner.Scan(ctx, resource)
				report, err := reportBuilder.GetReport()
				if err != nil {
					scanErr <- err
					return
				}
				list.Items = append(list.Items, report)
			}
			configReportChan <- list
			close(configReportChan)
		}(scanErr, configReportChan)

		// scan workload for vulnerabilities
		vulnReportChan := make(chan *v1alpha1.VulnerabilityReportList, 1)
		go func(scanErr chan error, reportChan chan *v1alpha1.VulnerabilityReportList) {
			defer wg.Done()
			kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				scanErr <- err
				return
			}
			workloads := getWorkloadResources(allResources)
			vulnScanner, err := getVulnerabilityScanner(ctx, cmd, kubeClientset, buildInfo, kubeClient)
			if err != nil {
				scanErr <- err
				return
			}
			list := &v1alpha1.VulnerabilityReportList{
				Items: []v1alpha1.VulnerabilityReport{},
			}
			for _, workload := range workloads {
				reports, err := vulnScanner.Scan(ctx, workload)
				if err != nil {
					scanErr <- err
					return
				}
				for _, report := range reports {
					list.Items = append(list.Items, report)
				}
			}
			reportChan <- list
			close(reportChan)
		}(scanErr, vulnReportChan)
		wg.Wait()
		if len(scanErr) != 0 {
			for e := range scanErr {
				return e
			}
		}
		printer, err := getPrinter(cmd)
		if err != nil {
			return err
		}
		for cReport := range configReportChan {
			printer.PrintObj(cReport, outWriter)
		}
		for vReport := range vulnReportChan {
			printer.PrintObj(vReport, outWriter)
		}
		return nil
	}
}

func getNamespaceFromArg(args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("required namespace arg not define")
	}
	return args[0], nil
}

func getWorkloadResources(allResources []kube.ObjectRef) []kube.ObjectRef {
	workloads := make([]kube.ObjectRef, 0)
	for _, resource := range allResources {
		if kube.IsWorkload(string(resource.Kind)) {
			workloads = append(workloads, resource)
		}
	}
	return workloads
}

func getPrinter(cmd *cobra.Command) (printers.ResourcePrinter, error) {
	format := cmd.Flag("output").Value.String()
	var printer printers.ResourcePrinter

	switch format {
	case "yaml", "json":
		printer, err := genericclioptions.NewPrintFlags("").
			WithTypeSetter(starboard.NewScheme()).
			WithDefaultOutput(format).
			ToPrinter()
		if err != nil {
			return nil, err
		}
		return printer, nil
	case "":
		printer = printers.NewTablePrinter()
		return printer, nil
	default:
		return nil, fmt.Errorf("invalid output format %q, allowed formats are: yaml,json", format)
	}
}

func getVulnerabilityScanner(ctx context.Context, cmd *cobra.Command, kubeClientset *kubernetes.Clientset, buildInfo starboard.BuildInfo, kubeClient client.Client) (*vulnerabilityreport.Scanner, error) {
	config, err := starboard.NewConfigManager(kubeClientset, starboard.NamespaceName).Read(ctx)
	if err != nil {
		return nil, err
	}
	opts, err := getScannerOpts(cmd)
	if err != nil {
		return nil, err
	}
	plugin, pluginContext, err := plugin.NewResolver().
		WithBuildInfo(buildInfo).
		WithNamespace(starboard.NamespaceName).
		WithServiceAccountName(starboard.ServiceAccountName).
		WithConfig(config).
		WithClient(kubeClient).
		GetVulnerabilityPlugin()
	if err != nil {
		return nil, err
	}
	scanner := vulnerabilityreport.NewScanner(kubeClientset, kubeClient, plugin, pluginContext, config, opts)
	return scanner, nil
}
