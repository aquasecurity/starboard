package cmd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/starboard"

	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/polaris/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewScanConfigAuditReportsCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configauditreports",
		Short: "Run a variety of checks to ensure that Kubernetes pods and controllers are configured using best practices",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}
			mapper, err := cf.ToRESTMapper()
			if err != nil {
				return err
			}
			workload, gvk, err := WorkloadFromArgs(mapper, ns, args)
			if err != nil {
				return err
			}
			config, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return err
			}
			opts, err := getScannerOpts(cmd)
			if err != nil {
				return err
			}
			report, owner, err := polaris.NewScanner(opts, clientset).Scan(ctx, workload, gvk)
			if err != nil {
				return err
			}
			starboardClientset, err := starboardapi.NewForConfig(config)
			if err != nil {
				return nil
			}
			err = crd.NewReadWriter(starboard.NewScheme(), starboardClientset).Write(ctx, report, owner)
			if err != nil {
				return err
			}
			return nil
		},
	}

	registerScannerOpts(cmd)

	return cmd
}
