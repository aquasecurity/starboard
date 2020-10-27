package resources

import (
	"fmt"
	"hash"
	"hash/fnv"

	"github.com/davecgh/go-spew/spew"
	"k8s.io/apimachinery/pkg/util/rand"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/starboard/pkg/kube"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

func GetContainerImagesFromPodSpec(spec corev1.PodSpec) kube.ContainerImages {
	images := kube.ContainerImages{}
	for _, container := range spec.Containers {
		images[container.Name] = container.Image
	}
	return images
}

func GetContainerImagesFromJob(job *batchv1.Job) (kube.ContainerImages, error) {
	var containerImagesAsJSON string
	var ok bool

	if containerImagesAsJSON, ok = job.Annotations[kube.AnnotationContainerImages]; !ok {
		return nil, fmt.Errorf("job does not have required annotation: %s", kube.AnnotationContainerImages)
	}
	containerImages := kube.ContainerImages{}
	err := containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing job annotation: %s: %w", kube.AnnotationContainerImages, err)
	}
	return containerImages, nil
}

// HasContainersReadyCondition iterates conditions of the specified Pod to check
// whether all containers in the Pod are ready.
func HasContainersReadyCondition(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.ContainersReady {
			return true
		}
	}
	return false
}

// GetImmediateOwnerReference returns the immediate owner of the specified Pod.
// For example, for a Pod controlled by a Deployment it will return the active ReplicaSet object,
// whereas for an unmanaged Pod the immediate owner is the Pod itself.
func GetImmediateOwnerReference(pod *corev1.Pod) kube.Object {
	ownerRef := metav1.GetControllerOf(pod)
	if ownerRef != nil {
		return kube.Object{
			Namespace: pod.Namespace,
			Kind:      kube.Kind(ownerRef.Kind),
			Name:      ownerRef.Name,
		}
	}
	return kube.Object{
		Namespace: pod.Namespace,
		Kind:      kube.KindPod,
		Name:      pod.Name,
	}
}

// ComputeHash returns a hash value calculated from pod spec.
// The hash will be safe encoded to avoid bad words.
func ComputeHash(spec corev1.PodSpec) string {
	podSpecHasher := fnv.New32a()
	DeepHashObject(podSpecHasher, spec)
	return rand.SafeEncodeString(fmt.Sprint(podSpecHasher.Sum32()))
}

// DeepHashObject writes specified object to hash using the spew library
// which follows pointers and prints actual values of the nested objects
// ensuring the hash does not change when a pointer changes.
func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}
