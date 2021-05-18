package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	starboardOperator "github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// TODO Rename from Object to PartialObject (consider embedding types.NamespacedName struct)
// Object is a simplified representation of a Kubernetes object.
// Each object has kind, which designates the type of the entity it represents.
// Objects have names and many of them live in namespaces.
type Object struct {
	Kind      Kind
	Name      string
	Namespace string
}

// Kind represents the type of a Kubernetes Object.
type Kind string

const (
	KindUnknown Kind = "Unknown"

	KindNode      Kind = "Node"
	KindNamespace Kind = "Namespace"

	KindPod                   Kind = "Pod"
	KindReplicaSet            Kind = "ReplicaSet"
	KindReplicationController Kind = "ReplicationController"
	KindDeployment            Kind = "Deployment"
	KindStatefulSet           Kind = "StatefulSet"
	KindDaemonSet             Kind = "DaemonSet"
	KindCronJob               Kind = "CronJob"
	KindJob                   Kind = "Job"
)

type ExecutionMode string

const (
	ExecutionModeCLI      ExecutionMode = "CLI"
	ExecutionModeOperator ExecutionMode = "Operator"
)

// IsBuiltInWorkload returns true if the specified v1.OwnerReference
// is a built-in Kubernetes workload, false otherwise.
func IsBuiltInWorkload(controller *metav1.OwnerReference) bool {
	return controller != nil &&
		(controller.Kind == string(KindReplicaSet) ||
			controller.Kind == string(KindReplicationController) ||
			controller.Kind == string(KindStatefulSet) ||
			controller.Kind == string(KindDaemonSet) ||
			controller.Kind == string(KindJob))
}

func ObjectFromLabelsSet(set labels.Set) (Object, error) {
	if !set.Has(starboard.LabelResourceKind) {
		return Object{}, fmt.Errorf("required label does not exist: %s", starboard.LabelResourceKind)
	}
	if !set.Has(starboard.LabelResourceName) {
		return Object{}, fmt.Errorf("required label does not exist: %s", starboard.LabelResourceName)
	}
	return Object{
		Kind:      Kind(set.Get(starboard.LabelResourceKind)),
		Name:      set.Get(starboard.LabelResourceName),
		Namespace: set.Get(starboard.LabelResourceNamespace),
	}, nil
}

func GVRForResource(mapper meta.RESTMapper, resource string) (gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, err error) {
	fullySpecifiedGVR, groupResource := schema.ParseResourceArg(strings.ToLower(resource))
	if fullySpecifiedGVR != nil {
		gvr, err = mapper.ResourceFor(*fullySpecifiedGVR)
		if err != nil {
			return
		}
	}
	if gvr.Empty() {
		gvr, err = mapper.ResourceFor(groupResource.WithVersion(""))
		if err != nil {
			return
		}
	}
	gvk, err = mapper.KindFor(gvr)
	return
}

// ContainerImages is a simple structure to hold the mapping between container names and container image references.
type ContainerImages map[string]string

func (ci ContainerImages) AsJSON() (string, error) {
	writer, err := json.Marshal(ci)
	if err != nil {
		return "", err
	}
	return string(writer), nil
}

func (ci ContainerImages) FromJSON(value string) error {
	return json.Unmarshal([]byte(value), &ci)
}

func KindForObject(object metav1.Object, scheme *runtime.Scheme) (string, error) {
	ro, ok := object.(runtime.Object)
	if !ok {
		return "", fmt.Errorf("%T is not a runtime.Object", object)
	}
	gvk, err := apiutil.GVKForObject(ro, scheme)
	if err != nil {
		return "", err
	}
	return gvk.Kind, nil
}

func GetPartialObjectFromKindAndNamespacedName(kind Kind, name types.NamespacedName) Object {
	return Object{
		Kind:      kind,
		Name:      name.Name,
		Namespace: name.Namespace,
	}
}

// GetPodSpec returns v1.PodSpec from the specified Kubernetes
// client.Object. Returns error if the given client.Object
// is not a Kubernetes workload.
func GetPodSpec(obj client.Object) (corev1.PodSpec, error) {
	switch t := obj.(type) {
	case *corev1.Pod:
		return (obj.(*corev1.Pod)).Spec, nil
	case *appsv1.Deployment:
		return (obj.(*appsv1.Deployment)).Spec.Template.Spec, nil
	case *appsv1.ReplicaSet:
		return (obj.(*appsv1.ReplicaSet)).Spec.Template.Spec, nil
	case *corev1.ReplicationController:
		return (obj.(*corev1.ReplicationController)).Spec.Template.Spec, nil
	case *appsv1.StatefulSet:
		return (obj.(*appsv1.StatefulSet)).Spec.Template.Spec, nil
	case *appsv1.DaemonSet:
		return (obj.(*appsv1.DaemonSet)).Spec.Template.Spec, nil
	case *batchv1beta1.CronJob:
		return (obj.(*batchv1beta1.CronJob)).Spec.JobTemplate.Spec.Template.Spec, nil
	case *batchv1.Job:
		return (obj.(*batchv1.Job)).Spec.Template.Spec, nil
	default:
		return corev1.PodSpec{}, fmt.Errorf("unsupported workload: %T", t)
	}
}

func (o *ObjectResolver) GetCustomAnnotationsFromConfig(ctx context.Context, executionMode ExecutionMode) (map[string]string, error) {
	var configMapName, configMapNamespace, customAnnotationsKey string
	switch executionMode {
	case ExecutionModeCLI:
		configMapName = starboard.ConfigMapName
		configMapNamespace = starboard.NamespaceName
		customAnnotationsKey = starboard.AnnotationCustomAnnotationsForScanJobPods
	case ExecutionModeOperator:
		configMapName = starboardOperator.ConfigMapName
		configMapNamespace = starboardOperator.NamespaceName
		customAnnotationsKey = starboardOperator.AnnotationCustomAnnotationsForScanJobPods
	default:
		return map[string]string{}, fmt.Errorf("unsupported execution mode provided: %s", executionMode)
	}

	configMap := &corev1.ConfigMap{}
	err := o.Client.Get(ctx, types.NamespacedName{Namespace: configMapNamespace, Name: configMapName}, configMap)
	if err != nil {
		return map[string]string{}, err
	}

	customAnnotationsStr, found := configMap.Data[customAnnotationsKey]
	if !found || strings.TrimSpace(customAnnotationsStr) == "" {
		return map[string]string{}, nil
	}

	customAnnotationsMap := map[string]string{}
	for _, annotation := range strings.Split(customAnnotationsStr, ",") {
		sepByEqual := strings.Split(annotation, "=")
		if len(sepByEqual) != 2 {
			return map[string]string{}, fmt.Errorf("custom annotations found to be wrongfully provided: %s", customAnnotationsStr)
		}
		key, value := sepByEqual[0], sepByEqual[1]
		customAnnotationsMap[key] = value
	}

	return customAnnotationsMap, nil
}

type ObjectResolver struct {
	client.Client
}

func (o *ObjectResolver) GetObjectFromPartialObject(ctx context.Context, workload Object) (client.Object, error) {
	var obj client.Object
	switch workload.Kind {
	case KindPod:
		obj = &corev1.Pod{}
	case KindReplicaSet:
		obj = &appsv1.ReplicaSet{}
	case KindReplicationController:
		obj = &corev1.ReplicationController{}
	case KindDeployment:
		obj = &appsv1.Deployment{}
	case KindStatefulSet:
		obj = &appsv1.StatefulSet{}
	case KindDaemonSet:
		obj = &appsv1.DaemonSet{}
	case KindCronJob:
		obj = &batchv1beta1.CronJob{}
	case KindJob:
		obj = &batchv1.Job{}
	default:
		return nil, fmt.Errorf("unknown kind: %s", workload.Kind)
	}
	err := o.Client.Get(ctx, types.NamespacedName{Name: workload.Name, Namespace: workload.Namespace}, obj)
	if err != nil {
		return nil, err
	}
	gvk, err := apiutil.GVKForObject(obj, o.Client.Scheme())
	if err != nil {
		return nil, err
	}
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	return obj, nil
}

// GetRelatedReplicasetName attempts to find the replicaset that is associated with
// the given owner. If the owner is a Deployment, it will look for a ReplicaSet
// that is controlled by the Deployment. If the owner is a Pod, it will look for
// the ReplicaSet that owns the Pod.
func (o *ObjectResolver) GetRelatedReplicasetName(ctx context.Context, object Object) (string, error) {
	switch object.Kind {
	case KindDeployment:
		return o.getActiveReplicaSetByDeployment(ctx, object)
	case KindPod:
		return o.getReplicaSetByPod(ctx, object)
	}
	return "", fmt.Errorf("can only get related ReplicaSet for Deployment or Pod, not %q", string(object.Kind))
}

func (o *ObjectResolver) getActiveReplicaSetByDeployment(ctx context.Context, object Object) (string, error) {
	deploy := &appsv1.Deployment{}
	err := o.Client.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Name}, deploy)
	if err != nil {
		return "", fmt.Errorf("getting deployment %q: %w", object.Namespace+"/"+object.Name, err)
	}
	var rsList appsv1.ReplicaSetList
	err = o.Client.List(ctx, &rsList, client.MatchingLabelsSelector{
		Selector: labels.SelectorFromSet(deploy.Spec.Selector.MatchLabels),
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

func (o *ObjectResolver) getReplicaSetByPod(ctx context.Context, object Object) (string, error) {
	pod := &corev1.Pod{}
	err := o.Client.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: object.Name}, pod)
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
