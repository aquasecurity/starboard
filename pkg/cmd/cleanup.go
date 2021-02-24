package cmd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewCleanupCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete Kubernetes resources created by Starboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			kubeConfig, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				return err
			}
			apiExtensionsClientset, err := apiextensionsv1.NewForConfig(kubeConfig)
			if err != nil {
				return err
			}
			configManager := starboard.NewConfigManager(kubeClientset, starboard.NamespaceName)
			return kube.NewCRManager(kubeClientset, apiExtensionsClientset, configManager).
				Cleanup(context.TODO())
		},
	}
	return cmd
}
