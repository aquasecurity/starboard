package kube

import (
	"context"
	"fmt"
	"hash"
	"hash/fnv"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/davecgh/go-spew/spew"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

	if containerImagesAsJSON, ok = job.Annotations[starboard.AnnotationContainerImages]; !ok {
		return nil, fmt.Errorf("required annotation not set: %s", starboard.AnnotationContainerImages)
	}
	containerImages := ContainerImages{}
	err := containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing annotation: %s: %w", starboard.AnnotationContainerImages, err)
	}
	return containerImages, nil
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

// GetReportsByLabel fetch reports by matching labels
func getReportsByLabel(ctx context.Context, resolver ObjectResolver, objectList client.ObjectList, namespace string,
	labels map[string]string) error {
	err := resolver.Client.List(ctx, objectList,
		client.InNamespace(namespace),
		client.MatchingLabels(labels))
	if err != nil {
		return fmt.Errorf("listing reports in namespace %s matching labels %v: %w", namespace,
			labels, err)
	}
	return err
}

// MarkOldReportForImmediateDeletion set old (historical replicaSets) reports with TTL = 0 for immediate deletion
func MarkOldReportForImmediateDeletion(ctx context.Context, resolver ObjectResolver, namespace string, resourceName string) error {
	annotation := map[string]string{
		v1alpha1.TTLReportAnnotation: time.Duration(0).String(),
	}
	resourceNameLabels := map[string]string{starboard.LabelResourceName: resourceName}
	err := markOldConfigAuditReports(ctx, resolver, namespace, resourceNameLabels, annotation)
	if err != nil {
		return err
	}
	return nil
}

func markOldConfigAuditReports(ctx context.Context, resolver ObjectResolver, namespace string, resourceNameLabels map[string]string, annotation map[string]string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var configAuditReportList v1alpha1.ConfigAuditReportList
		err := getReportsByLabel(ctx, resolver, &configAuditReportList, namespace, resourceNameLabels)
		if err != nil {
			return err
		}
		for _, report := range configAuditReportList.Items {
			err := markReportTTL(ctx, resolver, report.DeepCopy(), annotation)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func markReportTTL[T client.Object](ctx context.Context, resolver ObjectResolver, report T, annotation map[string]string) error {
	report.SetAnnotations(annotation)
	err := resolver.Client.Update(ctx, report)
	if err != nil {
		return err
	}
	return nil
}
