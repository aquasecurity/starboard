package cmd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/spf13/cobra"
	extensionsapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewInitCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create custom resource definitions used by starboard",
		Long: `Create all the resources used by starboard. It will create the following
in the cluster:

 - custom resource definitions
 - starboard namespace
 - starboard service account
 - starboard cluster role and cluster role binding
 - config map

The config map contains the default configuration parameters. However this
can be modified to change the behaviour of the scanner.

These resources can be removed from the cluster using the "cleanup" command.`,
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
			clientsetext, err := extensionsapi.NewForConfig(config)
			if err != nil {
				return err
			}
			return kube.NewCRManager(starboard.NewConfigManager(clientset, starboard.NamespaceName), clientset, clientsetext).
				Init(ctx)
		},
	}
	return cmd
}
