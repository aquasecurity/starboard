package cmd

import (
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/crd"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/trivy"
	secapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func GetVulnerabilitiesCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Aliases: []string{"vulns", "vuln"},
		Use:     "vulnerabilities (NAME | TYPE/NAME)",
		Short:   "Scan a given workload for vulnerabilities using Trivy scanner",
		Long: `Scan a given workload for vulnerabilities using Trivy scanner

TYPE is a Kubernetes workload. Shortcuts and API groups will be resolved, e.g. 'po' or 'deployments.apps'.
NAME is the name of a particular Kubernetes workload.
`,
		Example: `  # Scan a pod with the specified name
  kubectl starboard find vulnerabilities nginx

  # Scan a pod with the specified name in the specified namespace
  kubectl starboard find vulns po/nginx -n staging

  # Scan a replicaset with the specified name
  kubectl starboard find vuln replicaset/nginx

  # Scan a replicationcontroller with the given name
  kubectl starboard find vulns rc/nginx

  # Scan a deployment with the specified name
  kubectl starboard find vulns deployments.apps/nginx

  # Scan a daemonset with the specified name
  kubectl starboard find vulns daemonsets/nginx

  # Scan a statefulset with the specified name
  kubectl starboard find vulns sts/redis

  # Scan a job with the specified name
  kubectl starboard find vulns job/my-job

  # Scan a cronjob with the specified name
  kubectl starboard find vulns cj/my-cronjob`,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return
			}
			workload, err := WorkloadFromArgs(ns, args)
			if err != nil {
				return
			}
			config, err := cf.ToRESTConfig()
			if err != nil {
				return
			}
			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				return err
			}
			reports, err := trivy.NewScanner(clientset).Scan(workload)
			if err != nil {
				return
			}
			secClientset, err := secapi.NewForConfig(config)
			if err != nil {
				return
			}
			err = crd.NewWriter(secClientset).Write(workload, reports)
			return
		},
	}

	return cmd
}
