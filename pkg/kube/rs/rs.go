package rs

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// GetRelatedReplicasetName attempts to find the replicaset that is associated with
// the given owner. If the owner is a Deployment, it will look for a replicaset
// that is controlled by the Deployment. If the owner is a Pod, it will look for
// the replicaset that owns the Pod.
func GetRelatedReplicasetName(ctx context.Context, object kube.Object, clientset kubernetes.Interface) (string, error) {
	switch object.Kind {
	case kube.KindDeployment:
		return getActiveReplicaSetByDeployment(ctx, object, clientset)
	case kube.KindPod:
		return getReplicaSetByPod(ctx, object, clientset)
	}
	return "", fmt.Errorf("can only get related replicaset for deployment or pod, not %q", string(object.Kind))
}

func getActiveReplicaSetByDeployment(ctx context.Context, object kube.Object, clientset kubernetes.Interface) (string, error) {
	deploy, err := clientset.AppsV1().Deployments(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting deployment %q: %w", object.Name, err)
	}
	rsList, err := clientset.AppsV1().ReplicaSets(object.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(deploy.Spec.Selector.MatchLabels).String(),
	})
	if err != nil {
		return "", fmt.Errorf("listing replicasets for deployment %q: %w", object.Name, err)
	}
	if len(rsList.Items) == 0 {
		return "", fmt.Errorf("no replicasets associated with deployment %q", object.Name)
	}
	for _, rs := range rsList.Items {
		if deploy.Annotations["deployment.kubernetes.io/revision"] !=
			rs.Annotations["deployment.kubernetes.io/revision"] {
			continue
		}
		return rs.Name, nil
	}
	return "", fmt.Errorf("did not find an active replicaset associated with deployment %q", object.Name)
}

func getReplicaSetByPod(ctx context.Context, object kube.Object, clientset kubernetes.Interface) (string, error) {
	pod, err := clientset.CoreV1().Pods(object.Namespace).Get(ctx, object.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return "", fmt.Errorf("did not find a controller for pod %q", object.Name)
	}
	if controller.Kind != "ReplicaSet" {
		return "", fmt.Errorf("pod %q is controlled by a %q, want replicaset", object.Name, controller.Kind)
	}
	return controller.Name, nil
}
