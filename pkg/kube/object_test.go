package kube_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsBuiltInWorkload(t *testing.T) {
	testCases := []struct {
		kind              string
		isBuiltInWorkload bool
	}{
		{
			kind:              "ReplicationController",
			isBuiltInWorkload: true,
		},
		{
			kind:              "ReplicaSet",
			isBuiltInWorkload: true,
		},
		{
			kind:              "StatefulSet",
			isBuiltInWorkload: true,
		},
		{
			kind:              "DaemonSet",
			isBuiltInWorkload: true,
		},
		{
			kind:              "Job",
			isBuiltInWorkload: true,
		},
		{
			kind:              "ArgoCD",
			isBuiltInWorkload: false,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Should return %t when controller kind is %s", tc.isBuiltInWorkload, tc.kind), func(t *testing.T) {
			assert.Equal(t, tc.isBuiltInWorkload, kube.IsBuiltInWorkload(&metav1.OwnerReference{Kind: tc.kind}))
		})
	}
}

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
				starboard.LabelResourceKind:      "Deployment",
				starboard.LabelResourceName:      "my-deployment",
				starboard.LabelResourceNamespace: "my-namespace",
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
				starboard.LabelResourceKind: "Node",
				starboard.LabelResourceName: "my-node",
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
				starboard.LabelResourceName:      "my-deployment",
				starboard.LabelResourceNamespace: "my-namespace",
			},
			expectedError: errors.New("required label does not exist: starboard.resource.kind"),
		},
		{
			name: "Should return error when object name is not specified as label",
			labelsSet: labels.Set{
				starboard.LabelResourceKind: "Deployment",
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

func TestObjectResolver_GetRelatedReplicasetName(t *testing.T) {

	instance := &kube.ObjectResolver{Client: fake.NewClientBuilder().WithScheme(starboard.NewScheme()).WithObjects(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: corev1.NamespaceDefault,
				Labels: map[string]string{
					"app": "nginx",
				},
				Annotations: map[string]string{
					"deployment.kubernetes.io/revision": "2",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "nginx",
					},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-7ff78f74b9",
				Namespace: corev1.NamespaceDefault,
				Labels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "7ff78f74b9",
				},
				Annotations: map[string]string{
					"deployment.kubernetes.io/revision": "1",
				},
			},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":               "nginx",
						"pod-template-hash": "7ff78f74b9",
					},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-549f5fcb58",
				Namespace: corev1.NamespaceDefault,
				Labels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "549f5fcb58",
				},
				Annotations: map[string]string{
					"deployment.kubernetes.io/revision": "2",
				},
			},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":               "nginx",
						"pod-template-hash": "549f5fcb58",
					},
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-549f5fcb58-7cr5b",
				Namespace: corev1.NamespaceDefault,
				Labels: map[string]string{
					"app":               "nginx",
					"pod-hash-template": "549f5fcb58",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "apps/v1",
						Kind:               "ReplicaSet",
						Name:               "nginx-549f5fcb58",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(true),
					},
				},
			},
		},
	).Build()}

	t.Run("Should return error for unsupported kind", func(t *testing.T) {
		_, err := instance.GetRelatedReplicasetName(context.Background(), kube.Object{
			Kind:      kube.KindStatefulSet,
			Name:      "statefulapp",
			Namespace: corev1.NamespaceDefault,
		})
		require.EqualError(t, err, "can only get related ReplicaSet for Deployment or Pod, not \"StatefulSet\"")
	})

	t.Run("Should return ReplicaSet name for the specified Deployment", func(t *testing.T) {
		name, err := instance.GetRelatedReplicasetName(context.Background(), kube.Object{
			Kind:      kube.KindDeployment,
			Name:      "nginx",
			Namespace: corev1.NamespaceDefault,
		})
		require.NoError(t, err)
		assert.Equal(t, "nginx-549f5fcb58", name)
	})

	t.Run("Should return ReplicaSet name for the specified Deployment", func(t *testing.T) {
		name, err := instance.GetRelatedReplicasetName(context.Background(), kube.Object{
			Kind:      kube.KindPod,
			Name:      "nginx-549f5fcb58-7cr5b",
			Namespace: corev1.NamespaceDefault,
		})
		require.NoError(t, err)
		assert.Equal(t, "nginx-549f5fcb58", name)
	})

}

func TestGetCustomAnnotationsFromConfig(t *testing.T) {
	testCases := []struct {
		name                             string
		userProvidedCustomAnnotationsStr string
		expectedParsedCustomAnnotations  map[string]string
		expectedError                    string
	}{
		{
			name:                             "Should fetch and parse user-provided custom annotations successfully",
			userProvidedCustomAnnotationsStr: "foo=bar,a.b=x.y:z",
			expectedParsedCustomAnnotations: map[string]string{
				"foo": "bar",
				"a.b": "x.y:z",
			},
			expectedError: "",
		},
		{
			name:                             "Should gracefully utilise empty annotations if custom annotations are not provided by the user",
			userProvidedCustomAnnotationsStr: "",
			expectedParsedCustomAnnotations:  map[string]string{},
			expectedError:                    "",
		},
		{
			name:                             "Should throw an error if the custom annotations are provided in a wrong manner",
			userProvidedCustomAnnotationsStr: "a=b=c",
			expectedParsedCustomAnnotations:  map[string]string{},
			expectedError:                    "custom annotations found to be wrongfully provided: a=b=c",
		},
		{
			name:                             "Should throw an error if the custom annotations are provided in a wrong manner",
			userProvidedCustomAnnotationsStr: "foo",
			expectedParsedCustomAnnotations:  map[string]string{},
			expectedError:                    "custom annotations found to be wrongfully provided: foo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configMapForCLI := &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "starboard",
					Namespace: "starboard",
				},
				Data: map[string]string{
					"starboard.custom-annotations": tc.userProvidedCustomAnnotationsStr,
				},
			}
			configMapForOperator := &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "starboard",
					Namespace: "starboard-operator",
				},
				Data: map[string]string{
					"starboard-operator.custom-annotations": tc.userProvidedCustomAnnotationsStr,
				},
			}

			instance := &kube.ObjectResolver{Client: fake.NewClientBuilder().WithScheme(starboard.NewScheme()).WithObjects(
				configMapForCLI,
				configMapForOperator,
			).Build()}

			fetchedCustomAnnotationsForCLI, err := instance.GetCustomAnnotationsFromConfig(context.Background(), kube.ExecutionModeCLI)
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedParsedCustomAnnotations, fetchedCustomAnnotationsForCLI)
			}

			fetchedCustomAnnotationsForOperator, err := instance.GetCustomAnnotationsFromConfig(context.Background(), kube.ExecutionModeOperator)
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedParsedCustomAnnotations, fetchedCustomAnnotationsForOperator)
			}

		})
	}
}
