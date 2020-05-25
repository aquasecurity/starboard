package cmd

import (
	"github.com/aquasecurity/starboard/pkg/kubehunter"
	"github.com/aquasecurity/starboard/pkg/kubehunter/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func NewKubeHunterCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kube-hunter",
		Short: "Hunt for security weaknesses",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return
			}
			report, err := kubehunter.NewScanner(clientset).Scan()
			if err != nil {
				return
			}
			writer, err := crd.NewWriter(config)
			if err != nil {
				return
			}
			err = writer.Write(report, "cluster")
			if err != nil {
				return
			}
			return
		},
	}
	return cmd
}
