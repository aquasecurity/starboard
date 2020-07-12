package cmd

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/ext"
	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/kubebench/crd"
	"github.com/spf13/cobra"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
)

const (
	masterNodeLabel = "node-role.kubernetes.io/master"
)

func NewKubeBenchCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kube-bench",
		Short: "Run the CIS Kubernetes Benchmark https://www.cisecurity.org/benchmark/kubernetes",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx := context.Background()
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			kubernetesClientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return
			}
			opts, err := getScannerOpts(cmd)
			if err != nil {
				return
			}
			starboardClientset, err := starboard.NewForConfig(config)
			if err != nil {
				return
			}
			// List Nodes
			nodeList, err := kubernetesClientset.CoreV1().Nodes().List(ctx, meta.ListOptions{})
			if err != nil {
				err = fmt.Errorf("list nodes: %w", err)
				return
			}
			for _, nodeItem := range nodeList.Items {
				klog.V(3).Infof("Node name: %s/%s", nodeItem.Name, nodeItem.Labels[masterNodeLabel])
				report, node, err := kubebench.NewScanner(opts, kubernetesClientset).Scan(ctx, nodeItem.Name)
				if err != nil {
					break
				}
				err = crd.NewWriter(ext.NewSystemClock(), starboardClientset).Write(ctx, report, node)
			}

			return
		},
	}

	registerScannerOpts(cmd)

	return cmd
}
