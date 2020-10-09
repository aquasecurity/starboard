package controller_test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/starboard/pkg/operator/controller"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

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
		assert.Equal(t, controller.ComputeHash(spec1), controller.ComputeHash(spec2))
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
		assert.Equal(t, controller.ComputeHash(spec1), controller.ComputeHash(spec2))
	})

	t.Run("Should return unique hashes", func(t *testing.T) {
		hashes := make(map[string]bool)
		for tag := 0; tag < 100; tag++ {
			hash := controller.ComputeHash(corev1.PodSpec{
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
