package cmd

import (
	"context"
	"fmt"
	"sync"

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
			var wg sync.WaitGroup
			wg.Add(len(nodeList.Items))
			for _, nodeItem := range nodeList.Items {
				target := "node"
				if _, ok := nodeItem.Labels[masterNodeLabel]; ok {
					target = "master"
				}
				nodeName := nodeItem.Name
				go func() {
					klog.V(3).Infof("Node name: %s Label:%s", nodeName, target)
					report, node, err := kubebench.NewScanner(opts, kubernetesClientset).Scan(ctx, nodeName, target, &wg)

					if err != nil {
						klog.Warningf("Node name: %s Error NewScanner: %s", nodeName, err)
					}
					err = crd.NewWriter(ext.NewSystemClock(), starboardClientset).Write(ctx, report, node)
					if err != nil {
						klog.Warningf("Node name: %s Error NewWriter: %s", nodeName, err)
					}
				}()
			}
			wg.Wait()
			return
		},
	}

	registerScannerOpts(cmd)

	return cmd
}
