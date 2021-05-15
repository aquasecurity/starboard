package kube_test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetContainerImagesFromPodSpec(t *testing.T) {
	images := kube.GetContainerImagesFromPodSpec(corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "nginx",
				Image: "nginx:1.16",
			},
			{
				Name:  "sidecar",
				Image: "sidecar:1.32.7",
			},
		},
	})
	assert.Equal(t, kube.ContainerImages{
		"nginx":   "nginx:1.16",
		"sidecar": "sidecar:1.32.7",
	}, images)
}

func TestGetContainerImageDigestsFromPodStatus(t *testing.T) {
	images := kube.GetContainerImageDigestsFromPodStatus(corev1.PodStatus{
		InitContainerStatuses: []corev1.ContainerStatus{
			{
				Name:    "busybox",
				ImageID: "docker.io/library/busybox@sha256:be4684e4004560b2cd1f12148b7120b0ea69c385bcc9b12a637537a2c60f97fb",
			},
		},
		ContainerStatuses: []corev1.ContainerStatus{
			{
				Name:    "nginx",
				ImageID: "docker.io/library/nginx@sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
			},
			{
				Name:    "wordpress",
				ImageID: "docker.io/library/wordpress@sha256:69607dc78dda010e6708c6ced72c80563ad55b180286c66198b319bf0ee74173",
			},
		},
	})
	assert.Equal(t, kube.ContainerImages{
		"busybox":   "docker.io/library/busybox@sha256:be4684e4004560b2cd1f12148b7120b0ea69c385bcc9b12a637537a2c60f97fb",
		"nginx":     "docker.io/library/nginx@sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
		"wordpress": "docker.io/library/wordpress@sha256:69607dc78dda010e6708c6ced72c80563ad55b180286c66198b319bf0ee74173",
	}, images)
}

func TestGetContainerImagesFromJob(t *testing.T) {

	t.Run("Should return error when annotation is not set", func(t *testing.T) {
		_, err := kube.GetContainerImagesFromJob(&batchv1.Job{})
		require.EqualError(t, err, "required annotation not set: starboard.container-images")
	})

	t.Run("Should return error when annotation is set but has invalid value", func(t *testing.T) {
		_, err := kube.GetContainerImagesFromJob(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"starboard.container-images": ``,
				},
			},
		})
		require.EqualError(t, err, "parsing annotation: starboard.container-images: unexpected end of JSON input")
	})

	t.Run("Should return ContainerImages when annotation is set", func(t *testing.T) {
		images, err := kube.GetContainerImagesFromJob(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"starboard.container-images": `{"nginx":"nginx:1.16","sidecar":"sidecar:1.32.7"}`,
				},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, kube.ContainerImages{
			"nginx":   "nginx:1.16",
			"sidecar": "sidecar:1.32.7",
		}, images)
	})
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
		assert.Equal(t, kube.ComputeHash(spec1), kube.ComputeHash(spec2))
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
		assert.Equal(t, kube.ComputeHash(spec1), kube.ComputeHash(spec2))
	})

	t.Run("Should return unique hashes", func(t *testing.T) {
		hashes := make(map[string]bool)
		for tag := 0; tag < 100; tag++ {
			hash := kube.ComputeHash(corev1.PodSpec{
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
