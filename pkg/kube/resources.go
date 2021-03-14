package kube

import (
	"fmt"
	"hash"
	"hash/fnv"

	"github.com/davecgh/go-spew/spew"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
)

// GetContainerImagesFromPodSpec returns a map of container names
// to container images from the specified v1.PodSpec.
func GetContainerImagesFromPodSpec(spec corev1.PodSpec) ContainerImages {
	images := ContainerImages{}
	for _, container := range spec.Containers {
		images[container.Name] = container.Image
	}
	return images
}

// GetContainerImagesFromJob returns a map of container names
// to container images from the specified v1.Job.
// The mapping is encoded as JSON value of the AnnotationContainerImages
// annotation.
func GetContainerImagesFromJob(job *batchv1.Job) (ContainerImages, error) {
	var containerImagesAsJSON string
	var ok bool

	if containerImagesAsJSON, ok = job.Annotations[AnnotationContainerImages]; !ok {
		return nil, fmt.Errorf("required annotation not set: %s", AnnotationContainerImages)
	}
	containerImages := ContainerImages{}
	err := containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing annotation: %s: %w", AnnotationContainerImages, err)
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
// Pods created and controlled by third party frameworks, such as Argo workflow
// engine, are considered as unmanaged. Otherwise we'd need to maintain and
// extend the list of RBAC permissions over time.
// TODO Merge this method with ObjectResolver, which accepts kube.Object and resolves client.Object.
func GetImmediateOwnerReference(pod *corev1.Pod) Object {
	ownerRef := metav1.GetControllerOf(pod)

	if ownerRef != nil {
		switch ownerRef.Kind {
		case "Pod", "ReplicaSet", "ReplicationController", "Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job":
			return Object{
				Namespace: pod.Namespace,
				Kind:      Kind(ownerRef.Kind),
				Name:      ownerRef.Name,
			}
		}
	}

	// Pod owned by anything else is treated the same as an unmanaged pod
	return Object{
		Kind:      KindPod,
		Namespace: pod.Namespace,
		Name:      pod.Name,
	}
}

// ComputeHash returns a hash value calculated from a given object.
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
