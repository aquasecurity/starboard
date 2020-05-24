package cmd

import (
	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/polaris/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func GetPolarisCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "polaris",
		Short: "Run a variety of checks to ensure that Kubernetes pods and controllers are configured using best practices",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return
			}
			reports, err := polaris.NewScanner(clientset).Scan()
			if err != nil {
				return
			}
			starboardClientset, err := starboard.NewForConfig(config)
			if err != nil {
				return
			}
			err = crd.NewWriter(starboardClientset).WriteAll(reports)
			if err != nil {
				return
			}
			return
		},
	}
	return cmd
}
