package kube

import (
	"encoding/json"
	"fmt"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s.io/apimachinery/pkg/labels"
)

// Object is a simplified representation a Kubernetes object.
// Each object has kind, which designates the type of the entity it represents.
// Objects have names and many of them live in namespaces.
type Object struct {
	Kind      Kind
	Name      string
	Namespace string
	Group     string
	Version   string
	Resource  string
}

// Kind represents the type of a Kubernetes Object.
type Kind string

const (
	KindUnknown Kind = "Unknown"

	KindNode Kind = "Node"

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

func GvkFromResource(mapper meta.RESTMapper, resource string) (gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, err error) {
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

// Returns a string representing the workload, managing core api group as well
func FullQNForWorkload(object Object) (fqname string) {
	group := object.Group
	if len(group) > 0 {
		group = "." + group
	}
	fqname = fmt.Sprintf("%s/%s%s/%s/%s",
		object.Namespace,
		object.Kind,
		group,
		object.Version,
		object.Name,
	)
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

func GVKForObject(obj runtime.Object, scheme *runtime.Scheme) (schema.GroupVersionKind, error) {
	gvks, isUnversioned, err := scheme.ObjectKinds(obj)
	if err != nil {
		return schema.GroupVersionKind{}, err
	}
	if isUnversioned {
		return schema.GroupVersionKind{}, fmt.Errorf("cannot create group-version-kind for unversioned type %T", obj)
	}

	if len(gvks) < 1 {
		return schema.GroupVersionKind{}, fmt.Errorf("no group-version-kinds associated with type %T", obj)
	}
	if len(gvks) > 1 {
		// this should only trigger for things like metav1.XYZ --
		// normal versioned types should be fine
		return schema.GroupVersionKind{}, fmt.Errorf(
			"multiple group-version-kinds associated with type %T, refusing to guess at one", obj)
	}
	return gvks[0], nil
}

func KindForObject(object metav1.Object, scheme *runtime.Scheme) (string, error) {
	ro, ok := object.(runtime.Object)
	if !ok {
		return "", fmt.Errorf("%T is not a runtime.Object", object)
	}
	gvk, err := GVKForObject(ro, scheme)
	if err != nil {
		return "", err
	}
	return gvk.Kind, nil
}

func SetOwnerReference(owner, object metav1.Object, scheme *runtime.Scheme) error {
	// Validate the owner.
	ro, ok := owner.(runtime.Object)
	if !ok {
		return fmt.Errorf("%T is not a runtime.Object, cannot call SetOwnerReference", owner)
	}
	if err := validateOwner(owner, object); err != nil {
		return err
	}

	// Create a new owner ref.
	gvk, err := GVKForObject(ro, scheme)
	if err != nil {
		return err
	}
	ref := metav1.OwnerReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		UID:        owner.GetUID(),
		Name:       owner.GetName(),
	}

	// Update owner references and return.
	upsertOwnerRef(ref, object)
	return nil
}

func validateOwner(owner, object metav1.Object) error {
	ownerNs := owner.GetNamespace()
	if ownerNs != "" {
		objNs := object.GetNamespace()
		if objNs == "" {
			return fmt.Errorf("cluster-scoped resource must not have a namespace-scoped owner, owner's namespace %s", ownerNs)
		}
		if ownerNs != objNs {
			return fmt.Errorf("cross-namespace owner references are disallowed, owner's namespace %s, obj's namespace %s", owner.GetNamespace(), object.GetNamespace())
		}
	}
	return nil
}

func upsertOwnerRef(ref metav1.OwnerReference, object metav1.Object) {
	owners := object.GetOwnerReferences()
	idx := indexOwnerRef(owners, ref)
	if idx == -1 {
		owners = append(owners, ref)
	} else {
		owners[idx] = ref
	}
	object.SetOwnerReferences(owners)
}

// indexOwnerRef returns the index of the owner reference in the slice if found, or -1.
func indexOwnerRef(ownerReferences []metav1.OwnerReference, ref metav1.OwnerReference) int {
	for index, r := range ownerReferences {
		if referSameObject(r, ref) {
			return index
		}
	}
	return -1
}

// Returns true if a and b point to the same object
func referSameObject(a, b metav1.OwnerReference) bool {
	aGV, err := schema.ParseGroupVersion(a.APIVersion)
	if err != nil {
		return false
	}

	bGV, err := schema.ParseGroupVersion(b.APIVersion)
	if err != nil {
		return false
	}

	return aGV.Group == bGV.Group && a.Kind == b.Kind && a.Name == b.Name
}
