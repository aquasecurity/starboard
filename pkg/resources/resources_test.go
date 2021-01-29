package resources_test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/resources"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

func TestGetImmediateOwnerReference(t *testing.T) {

	testCases := []struct {
		name          string
		pod           *corev1.Pod
		expectedOwner kube.Object
	}{
		{
			name: "Should return pod as owner of unmanaged pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "unmanaged-pod",
				},
			},
			expectedOwner: kube.Object{
				Kind:      "Pod",
				Namespace: "foo",
				Name:      "unmanaged-pod",
			},
		},
		{
			name: "Should return ReplicaSet as owner of pod managed by Deployment",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "bar",
					Name:      "nginx-6d4cf56db6-8g9j6",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "apps/v1",
							Kind:       "ReplicaSet",
							Name:       "nginx-6d4cf56db6",
							Controller: pointer.BoolPtr(true),
						},
					},
				},
			},
			expectedOwner: kube.Object{
				Kind:      "ReplicaSet",
				Namespace: "bar",
				Name:      "nginx-6d4cf56db6",
			},
		},
		{
			name: "Should return pod as owner of static pod managed by kubelet",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "kube-system",
					Name:      "etcd-kind-control-plane",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "Node",
							Name:       "kind-control-plane",
							Controller: pointer.BoolPtr(true),
						},
					},
				},
			},
			expectedOwner: kube.Object{
				Kind:      "Pod",
				Namespace: "kube-system",
				Name:      "etcd-kind-control-plane",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			owner := resources.GetImmediateOwnerReference(tc.pod)
			assert.Equal(t, tc.expectedOwner, owner)
		})
	}

}

func TestComputeHash(t *testing.T) {

	booleanValue1 := true
	booleanValue2 := true
	booleanValue3 := false
	booleanValue1Ptr := &booleanValue1
	booleanValue2Ptr := &booleanValue2
	booleanValue3Ptr := &booleanValue3

	t.Run("Should return the same hash when pointers change but values stay the same", func(t *testing.T) {
		spec1 := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: booleanValue1Ptr,
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.14.2",
				},
			},
		}

		spec2 := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: booleanValue2Ptr,
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.14.2",
				},
			},
		}

		assert.NotSame(t, booleanValue1Ptr, booleanValue2Ptr)
		assert.Equal(t, booleanValue1, booleanValue2)
		assert.Equal(t, resources.ComputeHash(spec1), resources.ComputeHash(spec2))
	})

	t.Run("Should return different hash when pointers point to different values", func(t *testing.T) {
		spec1 := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: booleanValue1Ptr,
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.14.2",
				},
			},
		}

		spec2 := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: booleanValue2Ptr,
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.14.2",
				},
			},
		}

		assert.NotSame(t, booleanValue1Ptr, booleanValue3Ptr)
		assert.NotEqual(t, booleanValue1, booleanValue3)
		assert.Equal(t, resources.ComputeHash(spec1), resources.ComputeHash(spec2))
	})

	t.Run("Should return unique hashes", func(t *testing.T) {
		hashes := make(map[string]bool)
		for tag := 0; tag < 100; tag++ {
			hash := resources.ComputeHash(corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: fmt.Sprintf("nginx:%d", tag),
					},
				},
			})
			hashes[hash] = true
		}
		assert.Equal(t, 100, len(hashes))
	})

}
