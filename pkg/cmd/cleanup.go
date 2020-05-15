package cmd

import (
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/spf13/cobra"
	extapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func GetCleanupCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete custom resource definitions created by starboard",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return
			}
			clientsetext, err := extapi.NewForConfig(config)
			if err != nil {
				return
			}
			err = kube.NewCRManager(clientset, clientsetext).Cleanup()
			return
		},
	}
	return cmd
}
