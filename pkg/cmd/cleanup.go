package cmd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	extapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewCleanupCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete Kubernetes resources created by Starboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return err
			}
			clientsetext, err := extapi.NewForConfig(config)
			if err != nil {
				return err
			}
			configManager := starboard.NewConfigManager(clientset, starboard.NamespaceName)
			return kube.NewCRManager(clientset, clientsetext, configManager).
				Cleanup(context.TODO())
		},
	}
	return cmd
}
