package cmd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/ext"
	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/kubebench/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
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
			report, node, err := kubebench.NewScanner(kubernetesClientset).Scan(ctx)
			if err != nil {
				return
			}
			starboardClientset, err := starboard.NewForConfig(config)
			if err != nil {
				return
			}
			err = crd.NewWriter(ext.NewSystemClock(), starboardClientset).Write(ctx, report, node)
			return
		},
	}
	return cmd
}
