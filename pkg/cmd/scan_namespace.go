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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sync"
)

const (
	namespaceCmdShort = "Run a variety of checks to ensure that a given workload is configured using best practices and has no vulnerabilities"
)

func NewScanNamespaceCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "namespace (NAMESPACE)",
		Short: namespaceCmdShort,
		Args:  cobra.MaximumNArgs(1),
		RunE:  ScanNamespace(buildInfo, cf, out),
	}
	cmd.PersistentFlags().StringP("output", "o", "", "Output format. One of yaml|json")
	cmd.PersistentFlags().Bool("silent", false, "Silent progress bar printout")

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
		// scan for config audit
		allResources, err := getObjectsRef(ctx, dynaClient, namespace, getNamespaceGVR())
		if err != nil {
			return err
		}
		if len(allResources) == 0 {
			return nil
		}
		var wg sync.WaitGroup
		var numOfScanners = 1
		scheme := starboard.NewScheme()
		kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
		if err != nil {
			return err
		}
		configScanner := configauditreport.NewScanner(buildInfo, kubeClient)
		workloads := getWorkloadObjectRef(allResources)

		if len(workloads) > 0 {
			numOfScanners++
		}
		wg.Add(numOfScanners)
		scanErr := make(chan error, numOfScanners)
		reportChan := make(chan runtime.Object, numOfScanners)
		// scan config audit for misconfiguration
		go func(scanErr chan error, configReportChan chan runtime.Object) {
			defer wg.Done()
			configAuditReport, err := scanResourceConfig(ctx, allResources, cmd, configScanner)
			if err != nil {
				scanErr <- err
				return
			}
			reportChan <- configAuditReport
		}(scanErr, reportChan)

		// scan workloads for vulnerabilities
		vulnerabilityScanner, err := getVulnerabilityScanner(ctx, cmd, kubeConfig, buildInfo, kubeClient)
		if err != nil {
			return err
		}
		if len(workloads) > 0 {
			go func(scanErr chan error, reportChan chan runtime.Object) {
				defer wg.Done()
				vulnerabilityReport, err := scanVulnerabilities(ctx, workloads, cmd, vulnerabilityScanner)
				if err != nil {
					scanErr <- err
					return
				}
				reportChan <- vulnerabilityReport
			}(scanErr, reportChan)
		}
		wg.Wait()
		if err := checkScanningErrors(scanErr); err != nil {
			return err
		}
		err = printScannerReports(cmd, outWriter, reportChan)
		if err != nil {
			return err
		}
		return nil
	}
}

func scanVulnerabilities(ctx context.Context, workloads []kube.ObjectRef, cmd *cobra.Command, vulnerabilityScanner *vulnerabilityreport.Scanner) (*v1alpha1.VulnerabilityReportList, error) {
	bar := getProgressBar(len(workloads), "Vulnerabilities", cmd)
	list := &v1alpha1.VulnerabilityReportList{
		Items: []v1alpha1.VulnerabilityReport{},
	}
	for _, workload := range workloads {
		bar.Add(1)
		reports, err := vulnerabilityScanner.Scan(ctx, workload)
		if err != nil {
			return nil, err
		}
		for _, report := range reports {
			list.Items = append(list.Items, report)
		}
	}
	bar.Finish()
	return list, nil
}

func scanResourceConfig(ctx context.Context, allResources []kube.ObjectRef, cmd *cobra.Command, configScanner *configauditreport.Scanner) (runtime.Object, error) {
	bar := getProgressBar(len(allResources), "Resource Config", cmd)
	list := &v1alpha1.ConfigAuditReportList{
		Items: []v1alpha1.ConfigAuditReport{},
	}
	for _, resource := range allResources {
		bar.Add(1)
		reportBuilder, err := configScanner.Scan(ctx, resource)
		report, err := reportBuilder.GetReport()
		if err != nil {
			return nil, err
		}
		list.Items = append(list.Items, report)
	}
	bar.Finish()
	return list, nil
}

func getNamespaceFromArg(args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("required namespace arg not define")
	}
	return args[0], nil
}

func getVulnerabilityScanner(ctx context.Context, cmd *cobra.Command, kubeConfig *rest.Config, buildInfo starboard.BuildInfo, kubeClient client.Client) (*vulnerabilityreport.Scanner, error) {
	kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
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
