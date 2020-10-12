package cmd

import (
	"context"
	starboard "github.com/aquasecurity/starboard/pkg/kube"
	"github.com/spf13/cobra"
	"io"
	extensionsapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewInitCmd(cf *genericclioptions.ConfigFlags, outWriter io.Writer) *cobra.Command {
	options := &starboard.InitOptions{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create custom resource definitions used by starboard",
		Long: `
Create all the resources used by starboard.  It will create the following
in the cluster:

 - custom resource definitions
 - starboard namespace
 - starboard service account
 - starboard cluster role and cluster role binding
 - config map

The config map contains the default configuration parameters. However this
can be modified to change the behaviour of the scanner.

These resources can be removed from the cluster using the "cleanup" command.
`,
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
			clientsetext, err := extensionsapi.NewForConfig(config)
			if err != nil {
				return
			}

			err = starboard.NewCRManager(clientset, clientsetext, options, outWriter).Init(ctx)
			return
		},
	}
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", false, "Only print the object that would be sent, without sending it.")

	return cmd
}