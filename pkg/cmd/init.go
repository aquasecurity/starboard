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

func NewInitCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create Kubernetes resources used by Starboard",
		Long: `Create all the resources used by Starboard. It will create the following in your
Kubernetes cluster:

 - CustomResourceDefinition objects:
   - "vulnerabilityreports.aquasecurity.github.io"
   - "configauditreports.aquasecurity.github.io"
   - "ciskubebenchreports.aquasecurity.github.io"
   - "kubehunterreports.aquasecurity.github.io"
 - RBAC objects:
   - The "starboard" ClusterRole
   - The "starboard" ClusterRoleBinding
 - The "starboard" namespace with the following objects:
   - The "starboard" service account
   - The "starboard" ConfigMap
   - The "starboard" secret

The "starboard" ConfigMap and the "starboard" secret contain the default
config parameters. However this can be modified to change the behaviour
of the scanners.

All resources created by this command can be removed from the cluster using
the "cleanup" command.`,
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
				Init(context.TODO())
		},
	}
	return cmd
}
