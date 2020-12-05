package cmd

import (
	"context"
	"fmt"
	"sync"

	"github.com/aquasecurity/starboard/pkg/starboard"

	corev1 "k8s.io/api/core/v1"

	apis "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/kubebench/crd"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
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
		kubernetesConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		kubernetesClientset, err := kubernetes.NewForConfig(kubernetesConfig)
		if err != nil {
			return err
		}
		opts, err := getScannerOpts(cmd)
		if err != nil {
			return err
		}
		starboardClientset, err := apis.NewForConfig(kubernetesConfig)
		if err != nil {
			return err
		}
		nodeList, err := kubernetesClientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("listing nodes: %w", err)
		}
		config, err := starboard.NewConfigManager(kubernetesClientset, starboard.NamespaceName).Read(ctx)
		if err != nil {
			return err
		}

		scheme := starboard.NewScheme()
		scanner := kubebench.NewScanner(scheme, kubernetesClientset, config, opts)
		writer := crd.NewReadWriter(scheme, starboardClientset)

		var wg sync.WaitGroup

		for _, node := range nodeList.Items {
			wg.Add(1)
			go func(node corev1.Node) {
				defer wg.Done()

				report, err := scanner.Scan(ctx, node)

				if err != nil {
					klog.Errorf("Error while running kube-bench on node: %s: %v", node.Name, err)
					return
				}
				err = writer.Write(ctx, report, &node)
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
