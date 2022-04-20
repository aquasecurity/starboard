package cmd

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"io"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
		namespace, err := getNamespaceFromArg(args)
		if err != nil {
			return err
		}
		allResources, err := getObjectsRef(ctx, kubeConfig, namespace, getNamespaceGVR())
		if err != nil {
			return err
		}
		if len(allResources) == 0 {
			return nil
		}
		scheme := starboard.NewScheme()
		kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
		if err != nil {
			return err
		}
		configScanner := configauditreport.NewScanner(buildInfo, kubeClient)
		scanFuncs := []func() (runtime.Object, error){scanResourceConfig(ctx, allResources, cmd, configScanner)}
		workloads := getWorkloadObjectRef(allResources)
		if len(workloads) > 0 {
			vulnerabilityScanner, err := getVulnerabilityScanner(ctx, cmd, kubeConfig, buildInfo, kubeClient)
			if err != nil {
				return err
			}
			scanFuncs = append(scanFuncs, scanVulnerabilities(ctx, workloads, cmd, vulnerabilityScanner))
		}
		reportChan, errChan := executeChecks(scanFuncs)
		if err := checkScanningErrors(errChan); err != nil {
			return err
		}
		err = printScannerReports(cmd, outWriter, reportChan)
		if err != nil {
			return err
		}
		return nil
	}
}
func getNamespaceFromArg(args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("required namespace arg does not define")
	}
	return args[0], nil
}
