package cmd

import (
	"context"
	"fmt"
	"sync"

	"github.com/aquasecurity/starboard/pkg/starboard"

	corev1 "k8s.io/api/core/v1"

	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/kubebench/crd"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

func NewKubeBenchCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kube-bench",
		Short: "Run the CIS Kubernetes Benchmark https://www.cisecurity.org/benchmark/kubernetes",
		RunE: func(cmd *cobra.Command, args []string) error {
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
			starboardClientset, err := starboardapi.NewForConfig(kubernetesConfig)
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

			scanner := kubebench.NewScanner(config, opts, kubernetesClientset)
			writer := crd.NewReadWriter(starboard.NewScheme(), starboardClientset)

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
		},
	}

	registerScannerOpts(cmd)

	return cmd
}
