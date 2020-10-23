package cmd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/spf13/cobra"
	extapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewCleanupCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete custom resource definitions created by starboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
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
			return kube.NewCRManager(starboard.NewConfigManager(clientset, starboard.NamespaceName), clientset, clientsetext).
				Cleanup(ctx)
		},
	}
	return cmd
}
