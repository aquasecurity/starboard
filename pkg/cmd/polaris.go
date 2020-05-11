package cmd

import (
	secapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/polaris/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
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
			scanner, err := polaris.NewScanner(config)
			if err != nil {
				return
			}
			reports, err := scanner.Scan()
			if err != nil {
				return
			}
			secClientset, err := secapi.NewForConfig(config)
			if err != nil {
				return
			}
			err = crd.NewWriter(secClientset).WriteAll(reports)
			if err != nil {
				return
			}
			return
		},
	}
	return cmd
}
