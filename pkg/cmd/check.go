package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/plugin"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCheckCommand(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use: "check",
		Aliases: []string{
			"verify",
			"validate",
		},
		Short: "Check Kubernetes resources for configuration best practices and known vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
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
			kubeConfig, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				return err
			}
			scheme := starboard.NewScheme()
			kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
			opts, err := getScannerOpts(cmd)
			if err != nil {
				return err
			}
			config, err := starboard.NewConfigManager(kubeClientset, starboard.NamespaceName).Read(ctx)
			if err != nil {
				return err
			}

			checker := Checker{
				BuildInfo:   buildInfo,
				ConfigData:  config,
				ScannerOpts: opts,
				Scheme:      scheme,
				Clientset:   kubeClientset,
				Client:      kubeClient,
			}

			return checker.Check(ctx, workload, out)
		},
	}

	registerScannerOpts(cmd)

	return cmd
}

type Checker struct {
	starboard.BuildInfo
	starboard.ConfigData
	kube.ScannerOpts
	*runtime.Scheme
	*kubernetes.Clientset
	client.Client
}

func (c *Checker) Check(ctx context.Context, resource kube.ObjectRef, out io.Writer) error {
	switch resource.Kind {
	case kube.KindDeployment, kube.KindReplicaSet, kube.KindReplicationController, kube.KindPod, kube.KindStatefulSet, kube.KindDaemonSet, kube.KindJob, kube.KindCronJob:
		return c.checkWorkload(ctx, resource, out)
	case kube.KindNode:
		return c.checkNode(ctx, resource, out)
	default:
		return fmt.Errorf("unsupproted resource kind: %s", resource.Kind)
	}
}

func (c *Checker) checkWorkload(ctx context.Context, workload kube.ObjectRef, out io.Writer) error {
	pluginResolver := plugin.NewResolver().
		WithBuildInfo(c.BuildInfo).
		WithNamespace(starboard.NamespaceName).
		WithServiceAccountName(starboard.ServiceAccountName).
		WithConfig(c.ConfigData).
		WithClient(c.Client)

	vulnerabilityPlugin, pluginContext, err := pluginResolver.GetVulnerabilityPlugin()
	vulnerabilityScanner := vulnerabilityreport.NewScanner(c.Clientset, c.Client, vulnerabilityPlugin, pluginContext, c.ConfigData, c.ScannerOpts)
	reports, err := vulnerabilityScanner.Scan(ctx, workload)
	if err != nil {
		return err
	}

	for _, report := range reports {
		fmt.Fprintf(out, "%s/%s:%s\n", report.Report.Registry.Server, report.Report.Artifact.Repository, report.Report.Artifact.Tag)
		table := tablewriter.NewWriter(out)
		table.SetHeader([]string{"Vulnerability ID", "Severity", "Resource", "Version", "Fixed Version"})
		for _, c := range report.Report.Vulnerabilities {
			if c.FixedVersion == "" {
				continue
			}
			table.Append([]string{c.VulnerabilityID, string(c.Severity), c.Resource, c.InstalledVersion, c.FixedVersion})

		}
		table.Render()
	}

	configAuditPlugin, pluginContext, err := pluginResolver.GetConfigAuditPlugin()
	scanner := configauditreport.NewScanner(c.Clientset, c.Client, configAuditPlugin, pluginContext, c.ConfigData, c.ScannerOpts)
	reportBuilder, err := scanner.Scan(ctx, workload)
	if err != nil {
		return err
	}
	readWriter := configauditreport.NewReadWriter(c.Client)
	err = reportBuilder.Write(ctx, readWriter)
	if err != nil {
		return err
	}
	report, err := readWriter.FindReportByOwnerInHierarchy(ctx, workload)
	if err != nil {
		return nil
	}

	if report == nil {
		fmt.Fprintf(out, "No reports found in %s namespace.\n", workload.Namespace)
		return nil
	}

	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"Check ID", "Category", "Severity", "Message"})

	for _, c := range report.Report.Checks {
		if c.Success {
			continue
		}
		table.Append([]string{c.ID, c.Category, c.Severity, c.Message})
	}
	table.Render()
	return nil
}

func (c *Checker) checkNode(ctx context.Context, node kube.ObjectRef, out io.Writer) error {
	plugin := kubebench.NewKubeBenchPlugin(ext.NewSystemClock(), c.ConfigData)
	scanner := kubebench.NewScanner(c.Scheme, c.Clientset, plugin, c.ConfigData, c.ScannerOpts)

	nodes, err := GetNodes(ctx, c.Clientset, node.Name)
	if err != nil {
		return fmt.Errorf("getting nodes: %w", err)
	}

	report, err := scanner.Scan(ctx, nodes[0])

	for _, section := range report.Report.Sections {
		fmt.Fprintf(out, "[INFO] %s %s\n", section.ID, section.Text)
		for _, test := range section.Tests {
			fmt.Fprintf(out, "[INFO] %s %s\n", test.Section, test.Desc)
			for _, result := range test.Results {
				if result.Status == "PASS" {
					continue
				}
				fmt.Fprintf(out, "[%s] %s %s\n", result.Status, result.TestNumber, result.TestDesc)
			}
		}
	}

	return nil
}
