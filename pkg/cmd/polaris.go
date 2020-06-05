package cmd

import (
	"context"

	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/polaris/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewPolarisCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "polaris",
		Short: "Run a variety of checks to ensure that Kubernetes pods and controllers are configured using best practices",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx := context.Background()
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return
			}
			opts, err := getScannerOpts(cmd)
			if err != nil {
				return
			}
			reports, err := polaris.NewScanner(opts, clientset).Scan(ctx)
			if err != nil {
				return
			}
			starboardClientset, err := starboard.NewForConfig(config)
			if err != nil {
				return
			}
			err = crd.NewWriter(starboardClientset).WriteAll(ctx, reports)
			if err != nil {
				return
			}
			return
		},
	}

	registerScannerOpts(cmd)

	return cmd
}
