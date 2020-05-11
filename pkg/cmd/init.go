package cmd

import (
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/spf13/cobra"
	extapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func GetInitCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create custom resource definitions used by starboard",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			client, err := extapi.NewForConfig(config)
			if err != nil {
				return
			}
			crm, err := kube.NewCRManager(client)
			if err != nil {
				return
			}
			return crm.Init()
		},
	}
	return cmd
}
