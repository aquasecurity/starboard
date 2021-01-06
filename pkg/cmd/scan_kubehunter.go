package cmd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/starboard"

	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kubehunter"
	"github.com/aquasecurity/starboard/pkg/kubehunter/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

const (
	kubeHunterCmdShort = "Hunt for security weaknesses in your Kubernetes cluster"
)

func NewScanKubeHunterReportsCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kubehunterreports",
		Short: kubeHunterCmdShort,
		RunE:  ScanKubeHunterReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}

const (
	kubeHunterReportName = "cluster"
)

func ScanKubeHunterReports(cf *genericclioptions.ConfigFlags) func(cmd *cobra.Command, args []string) (err error) {
	return func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		kubernetesConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		kubernetesClientset, err := kubernetes.NewForConfig(kubernetesConfig)
		if err != nil {
			return err
		}
		opts, err := getScannerOpts(cmd)
		if err != nil {
			return err
		}
		config, err := starboard.NewConfigManager(kubernetesClientset, starboard.NamespaceName).Read(ctx)
		if err != nil {
			return err
		}

		report, err := kubehunter.NewScanner(starboard.NewScheme(), config, kubernetesClientset, opts).Scan(ctx)
		if err != nil {
			return err
		}
		starboardClientset, err := starboardapi.NewForConfig(kubernetesConfig)
		if err != nil {
			return err
		}
		return crd.NewWriter(starboardClientset).Write(ctx, report, kubeHunterReportName)
	}
}
