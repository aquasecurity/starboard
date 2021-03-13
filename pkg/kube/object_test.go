package kube_test

import (
	"errors"
	"testing"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestObjectFromLabelsSet(t *testing.T) {
	testCases := []struct {
		name           string
		labelsSet      labels.Set
		expectedObject kube.Object
		expectedError  error
	}{
		{
			name: "Should return object for namespaced object",
			labelsSet: labels.Set{
				kube.LabelResourceKind:      "Deployment",
				kube.LabelResourceName:      "my-deployment",
				kube.LabelResourceNamespace: "my-namespace",
			},
			expectedObject: kube.Object{
				Kind:      kube.KindDeployment,
				Name:      "my-deployment",
				Namespace: "my-namespace",
			},
		},
		{
			name: "Should return object for cluster-scoped object",
			labelsSet: labels.Set{
				kube.LabelResourceKind: "Node",
				kube.LabelResourceName: "my-node",
			},
			expectedObject: kube.Object{
				Kind:      kube.KindNode,
				Name:      "my-node",
				Namespace: "",
			},
		},
		{
			name: "Should return error when object kind is not specified as label",
			labelsSet: labels.Set{
				kube.LabelResourceName:      "my-deployment",
				kube.LabelResourceNamespace: "my-namespace",
			},
			expectedError: errors.New("required label does not exist: starboard.resource.kind"),
		},
		{
			name: "Should return error when object name is not specified as label",
			labelsSet: labels.Set{
				kube.LabelResourceKind: "Deployment",
			},
			expectedError: errors.New("required label does not exist: starboard.resource.name"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obj, err := kube.ObjectFromLabelsSet(tc.labelsSet)
			switch {
			case tc.expectedError == nil:
				require.NoError(t, err)
				assert.Equal(t, tc.expectedObject, obj)
			default:
				assert.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}
}

func TestContainerImages_AsJSON_And_FromJSON(t *testing.T) {
	containerImages := kube.ContainerImages{
		"nginx": "nginx:1.16",
		"redis": "core.harbor.domain:8443/library/redis:5",
	}
	value, err := containerImages.AsJSON()
	require.NoError(t, err)

	newContainerImages := kube.ContainerImages{}
	err = newContainerImages.FromJSON(value)
	require.NoError(t, err)
	assert.Equal(t, containerImages, newContainerImages)
}

func TestGetPartialObjectFromKindAndNamespacedName(t *testing.T) {
	partial := kube.GetPartialObjectFromKindAndNamespacedName(kube.KindReplicaSet, types.NamespacedName{
		Namespace: "prod",
		Name:      "wordpress",
	})
	assert.Equal(t, kube.Object{
		Kind:      kube.KindReplicaSet,
		Name:      "wordpress",
		Namespace: "prod",
	}, partial)
}

func TestGetPodSpec(t *testing.T) {
	testCases := []struct {
		name            string
		object          client.Object
		expectedPodSpec corev1.PodSpec
		expectedError   string
	}{
		{
			name: "Should return PodSpec for Pod",
			object: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "pod",
							Image: "pod:1.3",
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "pod",
						Image: "pod:1.3",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for Deployment",
			object: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "deployment",
									Image: "deployment:2.4",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "deployment",
						Image: "deployment:2.4",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for ReplicaSet",
			object: &appsv1.ReplicaSet{
				Spec: appsv1.ReplicaSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "replicaset",
									Image: "replicaset:3.17",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "replicaset",
						Image: "replicaset:3.17",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for ReplicationController",
			object: &corev1.ReplicationController{
				Spec: corev1.ReplicationControllerSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "replicationcontroller",
									Image: "replicationcontroller:latest",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "replicationcontroller",
						Image: "replicationcontroller:latest",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for StatefulSet",
			object: &appsv1.StatefulSet{
				Spec: appsv1.StatefulSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "statefulset",
									Image: "statefulset:8",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "statefulset",
						Image: "statefulset:8",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for DaemonSet",
			object: &appsv1.DaemonSet{
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "daemonset",
									Image: "daemonset:1.1",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "daemonset",
						Image: "daemonset:1.1",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for CronJob",
			object: &batchv1beta1.CronJob{
				Spec: batchv1beta1.CronJobSpec{
					JobTemplate: batchv1beta1.JobTemplateSpec{
						Spec: batchv1.JobSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:  "cronjob",
											Image: "cronjob:5",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "cronjob",
						Image: "cronjob:5",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for Job",
			object: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "job",
									Image: "job:2.8.2",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "job",
						Image: "job:2.8.2",
					},
				},
			},
		},
		{
			name:          "Should return error for Service",
			object:        &corev1.Service{},
			expectedError: "unsupported workload: *v1.Service",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			podSpec, err := kube.GetPodSpec(tc.object)
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedPodSpec, podSpec)
			}

		})
	}
}
