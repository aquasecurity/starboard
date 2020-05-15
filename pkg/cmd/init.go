package cmd

import (
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/spf13/cobra"
	extensionsapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
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
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return
			}
			clientsetext, err := extensionsapi.NewForConfig(config)
			if err != nil {
				return
			}
			err = kube.NewCRManager(clientset, clientsetext).Init()
			return
		},
	}
	return cmd
}
