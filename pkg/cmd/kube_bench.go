package cmd

import (
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/kubebench/crd"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func GetKubeBenchCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kube-bench",
		Short: "Run the CIS Kubernetes Benchmark https://www.cisecurity.org/benchmark/kubernetes",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			scanner, err := kubebench.NewScanner(config)
			if err != nil {
				return
			}
			report, node, err := scanner.Scan()
			if err != nil {
				return
			}
			writer, err := crd.NewWriter(config)
			if err != nil {
				return
			}
			err = writer.Write(report, node)
			return
		},
	}
	return cmd
}
