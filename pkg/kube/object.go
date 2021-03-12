package kube

import (
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

func ObjectFromLabelsSet(set labels.Set) (Object, error) {
	if !set.Has(LabelResourceKind) {
		return Object{}, fmt.Errorf("required label does not exist: %s", LabelResourceKind)
	}
	if !set.Has(LabelResourceName) {
		return Object{}, fmt.Errorf("required label does not exist: %s", LabelResourceName)
	}
	return Object{
		Kind:      Kind(set.Get(LabelResourceKind)),
		Name:      set.Get(LabelResourceName),
		Namespace: set.Get(LabelResourceNamespace),
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
