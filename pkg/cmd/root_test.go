package cmd

import (
	"errors"
	"testing"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/stretchr/testify/assert"
)

func TestWorkloadFromArgs(t *testing.T) {

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
			name:             "Should return Pod/my-pod when kind is specified as po",
			givenArgs:        []string{"po/my-pod"},
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
			name:             "Should return ReplicaSet/my-rs when kind is specified as rs",
			givenArgs:        []string{"rs/my-rs"},
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
			name:             "Should return ReplicationController/my-rc when kind is specified as rc",
			givenArgs:        []string{"rc/my-rc"},
			expectedWorkload: kube.Object{Kind: kube.KindReplicationController, Name: "my-rc"},
		},
		{
			name:             "Should return Deployment/my-deployment when kind is specified as deployments.apps",
			givenArgs:        []string{"deploy/my-deployment"},
			expectedWorkload: kube.Object{Kind: kube.KindDeployment, Name: "my-deployment"},
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
			name:             "Should return Deployment/my-deployment when kind is specified as deploy",
			givenArgs:        []string{"deploy/my-deployment"},
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
			name:             "Should return StatefulSet/my-sts when kind is specified as sts",
			givenArgs:        []string{"sts/my-sts"},
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
			name:             "Should return CronJob/my-cj when kind is specified as cj",
			givenArgs:        []string{"cj/my-cj"},
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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			workload, err := WorkloadFromArgs("", tc.givenArgs)
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error())
			default:
				assert.Equal(t, tc.expectedWorkload, workload)
			}
		})
	}

}
