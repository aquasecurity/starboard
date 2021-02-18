package cmd

import (
	"context"
	"fmt"
	"sync"

	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	kubeBenchCmdShort = "Run the CIS Kubernetes Benchmark for each node of your cluster"
)

func NewScanKubeBenchReportsCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ciskubebenchreports",
		Short: kubeBenchCmdShort,
		RunE:  ScanKubeBenchReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}

func ScanKubeBenchReports(cf *genericclioptions.ConfigFlags) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		kubeConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			return err
		}
		opts, err := getScannerOpts(cmd)
		if err != nil {
			return err
		}
		nodeList, err := kubeClientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("listing nodes: %w", err)
		}
		config, err := starboard.NewConfigManager(kubeClientset, starboard.NamespaceName).Read(ctx)
		if err != nil {
			return err
		}

		scheme := starboard.NewScheme()
		plugin := kubebench.NewKubeBenchPlugin(ext.NewSystemClock(), config)
		scanner := kubebench.NewScanner(scheme, kubeClientset, opts, plugin)

		kubeClient, err := client.New(kubeConfig, client.Options{
			Scheme: scheme,
		})
		if err != nil {
			return err
		}

		writer := kubebench.NewReadWriter(kubeClient)

		// TODO Move this logic to scanner.ScanAll() method. We should not mix discovery / scanning logic with the CLI.
		var wg sync.WaitGroup

		for _, node := range nodeList.Items {

			nodeValueLabel, exist := node.GetObjectMeta().GetLabels()["kubernetes.io/os"]
			if exist && nodeValueLabel != "linux" {
				klog.V(3).Infof("Skipping non linux node: %v %v", node.Name, node.Labels)
				continue
			}

			wg.Add(1)
			go func(node corev1.Node) {
				defer wg.Done()

				report, err := scanner.Scan(ctx, node)

				if err != nil {
					klog.Errorf("Error while running kube-bench on node: %s: %v", node.Name, err)
					return
				}
				err = writer.Write(ctx, report)
				if err != nil {
					klog.Errorf("Error while writing kube-bench report for node: %s: %v", node.Name, err)
					return
				}
			}(node)
		}

		wg.Wait()
		return nil
	}
}
