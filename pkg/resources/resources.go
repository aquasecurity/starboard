package resources

import (
	"fmt"
	"hash"
	"hash/fnv"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/davecgh/go-spew/spew"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
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

// GetImmediateOwnerReference returns the immediate owner of the specified pod.
// For example, for a pod controlled by a Deployment it will return the active
// ReplicaSet, whereas for an unmanaged pod the immediate owner is the pod
// itself.
//
// Note that kubelet can manage pods independently by reading pod definition
// files from a configured host directory (typically /etc/kubernetes/manifests).
// Such pods are called *static pods* and are owned by a cluster Node.
// In this case we treat them as unmanaged pods. (Otherwise we'd require
// cluster-scoped permissions to get Nodes in order to set the owner reference
// when we create an instance of custom security report.)
//
// TODO Merge this method with OwnerResolver, which accepts kube.Object and resolves client.Object.
func GetImmediateOwnerReference(pod *corev1.Pod) kube.Object {
	ownerRef := metav1.GetControllerOf(pod)

	if ownerRef != nil {
		if ownerRef.Kind == "Node" {
			// Static pod ~ unmanaged pod
			return kube.Object{
				Kind:      kube.KindPod,
				Namespace: pod.Namespace,
				Name:      pod.Name,
			}
		}

		return kube.Object{
			Namespace: pod.Namespace,
			Kind:      kube.Kind(ownerRef.Kind),
			Name:      ownerRef.Name,
		}
	}
	return kube.Object{
		Kind:      kube.KindPod,
		Namespace: pod.Namespace,
		Name:      pod.Name,
	}
}

// ComputeHash returns a hash value calculated from pod spec.
// The hash will be safe encoded to avoid bad words.
func ComputeHash(obj interface{}) string {
	podSpecHasher := fnv.New32a()
	DeepHashObject(podSpecHasher, obj)
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
