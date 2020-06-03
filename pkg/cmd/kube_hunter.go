package cmd

import (
	"context"

	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kubehunter"
	"github.com/aquasecurity/starboard/pkg/kubehunter/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewKubeHunterCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kube-hunter",
		Short: "Hunt for security weaknesses",
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
			report, err := kubehunter.NewScanner(kubernetesClientset).Scan(ctx)
			if err != nil {
				return
			}
			starboardClientset, err := starboardapi.NewForConfig(config)
			if err != nil {
				return
			}
			err = crd.NewWriter(starboardClientset).Write(ctx, report, "cluster")
			if err != nil {
				return
			}
			return
		},
	}
	return cmd
}
