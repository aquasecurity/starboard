package itest

import (
	"errors"
	"os"

	"github.com/aquasecurity/starboard/pkg/cmd"
	"github.com/aquasecurity/starboard/pkg/kube"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

var _ = Describe("Core Functionalities", func() {
	FDescribe("Resolving workloads", func() {
		testCases := []struct {
			name string

			givenArgs []string

			expectedWorkload kube.Object
			expectedError    error
		}{
			{
				name:             "Should return Pod/my-pod when kind is not explicitly specified",
				givenArgs:        []string{"my-pod"},
				expectedWorkload: kube.Object{Kind: kube.KindPod, Name: "my-pod"},
			},
			{
				name:             "Should return Pod/my-pod when kind is specified as pods",
				givenArgs:        []string{"pods/my-pod"},
				expectedWorkload: kube.Object{Kind: kube.KindPod, Name: "my-pod"},
			},
			{
				name:             "Should return Pod/my-pod when kind is specified as pod",
				givenArgs:        []string{"pod/my-pod"},
				expectedWorkload: kube.Object{Kind: kube.KindPod, Name: "my-pod"},
			},
			{
				name:             "Should return ReplicaSet/my-rs when kind is specified as replicasets.apps",
				givenArgs:        []string{"replicasets.apps/my-rs"},
				expectedWorkload: kube.Object{Kind: kube.KindReplicaSet, Name: "my-rs"},
			},
			{
				name:             "Should return ReplicaSet/my-rs when kind is specified as replicasets",
				givenArgs:        []string{"replicasets/my-rs"},
				expectedWorkload: kube.Object{Kind: kube.KindReplicaSet, Name: "my-rs"},
			},
			{
				name:             "Should return ReplicaSet/my-rs when kind is specified as replicaset",
				givenArgs:        []string{"replicaset/my-rs"},
				expectedWorkload: kube.Object{Kind: kube.KindReplicaSet, Name: "my-rs"},
			},
			{
				name:             "Should return ReplicationController/my-rc when kind is specified as replicationcontrollers",
				givenArgs:        []string{"replicationcontrollers/my-rc"},
				expectedWorkload: kube.Object{Kind: kube.KindReplicationController, Name: "my-rc"},
			},
			{
				name:             "Should return ReplicationController/my-rc when kind is specified as replicationcontroller",
				givenArgs:        []string{"replicationcontroller/my-rc"},
				expectedWorkload: kube.Object{Kind: kube.KindReplicationController, Name: "my-rc"},
			},
			{
				name:             "Should return Deployment/my-deployment when kind is specified as deployments",
				givenArgs:        []string{"deployments/my-deployment"},
				expectedWorkload: kube.Object{Kind: kube.KindDeployment, Name: "my-deployment"},
			},
			{
				name:             "Should return Deployment/my-deployment when kind is specified as deployment",
				givenArgs:        []string{"deployment/my-deployment"},
				expectedWorkload: kube.Object{Kind: kube.KindDeployment, Name: "my-deployment"},
			},
			{
				name:             "Should return DaemonSet/my-ds when kind is specified as daemonsets.apps",
				givenArgs:        []string{"daemonsets/my-ds"},
				expectedWorkload: kube.Object{Kind: kube.KindDaemonSet, Name: "my-ds"},
			},
			{
				name:             "Should return DaemonSet/my-ds when kind is specified as daemonsets",
				givenArgs:        []string{"daemonsets/my-ds"},
				expectedWorkload: kube.Object{Kind: kube.KindDaemonSet, Name: "my-ds"},
			},
			{
				name:             "Should return DaemonSet/my-ds when kind is specified as daemonset",
				givenArgs:        []string{"daemonsets/my-ds"},
				expectedWorkload: kube.Object{Kind: kube.KindDaemonSet, Name: "my-ds"},
			},
			{
				name:             "Should return DaemonSet/my-ds when kind is specified as ds",
				givenArgs:        []string{"daemonsets/my-ds"},
				expectedWorkload: kube.Object{Kind: kube.KindDaemonSet, Name: "my-ds"},
			},
			{
				name:             "Should return StatefulSet/my-sts when kind is specified as statefulsets.apps",
				givenArgs:        []string{"statefulsets.apps/my-sts"},
				expectedWorkload: kube.Object{Kind: kube.KindStatefulSet, Name: "my-sts"},
			},
			{
				name:             "Should return StatefulSet/my-sts when kind is specified as statefulsets",
				givenArgs:        []string{"statefulsets/my-sts"},
				expectedWorkload: kube.Object{Kind: kube.KindStatefulSet, Name: "my-sts"},
			},
			{
				name:             "Should return StatefulSet/my-sts when kind is specified as statefulset",
				givenArgs:        []string{"statefulset/my-sts"},
				expectedWorkload: kube.Object{Kind: kube.KindStatefulSet, Name: "my-sts"},
			},
			{
				name:             "Should return CronJob/my-cj when kind is specified as cronjobs.batch",
				givenArgs:        []string{"cronjobs.batch/my-cj"},
				expectedWorkload: kube.Object{Kind: kube.KindCronJob, Name: "my-cj"},
			},
			{
				name:             "Should return CronJob/my-cj when kind is specified as cronjob.batch",
				givenArgs:        []string{"cronjob.batch/my-cj"},
				expectedWorkload: kube.Object{Kind: kube.KindCronJob, Name: "my-cj"},
			},
			{
				name:             "Should return CronJob/my-cj when kind is specified as cronjobs",
				givenArgs:        []string{"cronjobs/my-cj"},
				expectedWorkload: kube.Object{Kind: kube.KindCronJob, Name: "my-cj"},
			},
			{
				name:             "Should return CronJob/my-cj when kind is specified as cronjob",
				givenArgs:        []string{"cronjob/my-cj"},
				expectedWorkload: kube.Object{Kind: kube.KindCronJob, Name: "my-cj"},
			},
			{
				name:             "Should return Job/my-job when kind is specified as jobs.batch",
				givenArgs:        []string{"jobs.batch/my-job"},
				expectedWorkload: kube.Object{Kind: kube.KindJob, Name: "my-job"},
			},
			{
				name:             "Should return Job/my-job when kind is specified as job.batch",
				givenArgs:        []string{"job.batch/my-job"},
				expectedWorkload: kube.Object{Kind: kube.KindJob, Name: "my-job"},
			},
			{
				name:             "Should return Job/my-job when kind is specified as jobs",
				givenArgs:        []string{"jobs/my-job"},
				expectedWorkload: kube.Object{Kind: kube.KindJob, Name: "my-job"},
			},
			{
				name:             "Should return Job/my-job when kind is specified as job",
				givenArgs:        []string{"job/my-job"},
				expectedWorkload: kube.Object{Kind: kube.KindJob, Name: "my-job"},
			},
			{
				name:             "Should return error when neither workload kind nor name is specified",
				givenArgs:        []string{},
				expectedWorkload: kube.Object{},
				expectedError:    errors.New("required workload kind and name not specified"),
			},
			{
				name:             "Should return error when kind is unrecognized",
				givenArgs:        []string{"xpod/my-pod"},
				expectedWorkload: kube.Object{},
				expectedError:    errors.New("unrecognized resource: xpod"),
			},
			{
				name:          "Should return error when workload name is blank",
				givenArgs:     []string{"pod/"},
				expectedError: errors.New("required workload name is blank"),
			},
		}

		config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		Expect(err).ToNot(HaveOccurred())
		kubernetesClientset, err = kubernetes.NewForConfig(config)
		Expect(err).ToNot(HaveOccurred())
		groupResources, err := restmapper.GetAPIGroupResources(kubernetesClientset.Discovery())
		Expect(err).ToNot(HaveOccurred())

		// For some reason this mapper cannot resolve shortnames, this is not the case
		// with the mapper we get from genericclioptions (which we actually use)
		// TODO: find a way to get a mapper that maps shortnames.
		restMapper := restmapper.NewDiscoveryRESTMapper(groupResources)

		Describe("Should map kinds correctly", func() {
			It("", func() {
				for _, tc := range testCases {
					workload, err := cmd.WorkloadFromArgs(restMapper, "", tc.givenArgs)
					switch {
					case tc.expectedError != nil:
						Expect(err).To(HaveOccurred())
					default:
						Expect(err).ToNot(HaveOccurred())
						Expect(workload.Kind).To(Equal(tc.expectedWorkload.Kind))
						Expect(workload.Name).To(Equal(tc.expectedWorkload.Name))
					}
				}
			})
		})
	})
})
