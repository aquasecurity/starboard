package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aquasecurity/starboard/pkg/starboard"
	ocpappsv1 "github.com/openshift/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	extensionv1beta1 "k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingbetav1 "k8s.io/api/networking/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// ObjectRef is a simplified representation of a Kubernetes client.Object.
// Each object has Kind, which designates the type of the entity it represents.
// Objects have names and many of them live in namespaces.
type ObjectRef struct {
	Kind      Kind
	Name      string
	Namespace string
}

// Kind represents the type of Kubernetes client.Object.
type Kind string

const (
	KindUnknown Kind = "Unknown"

	KindNode      Kind = "Node"
	KindNamespace Kind = "Namespace"

	KindPod                   Kind = "Pod"
	KindReplicaSet            Kind = "ReplicaSet"
	KindReplicationController Kind = "ReplicationController"
	KindDeployment            Kind = "Deployment"
	KindDeploymentConfig      Kind = "DeploymentConfig"
	KindStatefulSet           Kind = "StatefulSet"
	KindDaemonSet             Kind = "DaemonSet"
	KindCronJob               Kind = "CronJob"
	KindJob                   Kind = "Job"
	KindService               Kind = "Service"
	KindConfigMap             Kind = "ConfigMap"
	KindRole                  Kind = "Role"
	KindRoleBinding           Kind = "RoleBinding"
	KindNetworkPolicy         Kind = "NetworkPolicy"
	KindIngress               Kind = "Ingress"
	KindResourceQuota         Kind = "ResourceQuota"
	KindLimitRange            Kind = "LimitRange"

	KindClusterRole              Kind = "ClusterRole"
	KindClusterRoleBindings      Kind = "ClusterRoleBinding"
	KindCustomResourceDefinition Kind = "CustomResourceDefinition"
	KindPodSecurityPolicy        Kind = "PodSecurityPolicy"
)

const (
	cronJobResource           = "cronjobs"
	ingressResource           = "ingress"
	apiBatchV1beta1CronJob    = "batch/v1beta1, Kind=CronJob"
	apiBatchV1CronJob         = "batch/v1, Kind=CronJob"
	apiNetworkV1betaIngress   = "networking.k8s.io/v1beta1, Kind=Ingress"
	apiNetworkV1Ingress       = "networking.k8s.io/v1, Kind=Ingress"
	apiExtensionV1betaIngress = "extensions/v1beta1, Kind=Ingress"
)

const (
	deploymentAnnotation       string = "deployment.kubernetes.io/revision"
	deploymentConfigAnnotation string = "openshift.io/deployment-config.latest-version"

	DeployerPodForDeploymentLabel string = "openshift.io/deployer-pod-for.name"
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

// IsWorkload returns true if the specified resource kinds represents Kubernetes
// workload, false otherwise.
func IsWorkload(kind string) bool {
	return kind == "Pod" ||
		kind == "Deployment" ||
		kind == "ReplicaSet" ||
		kind == "ReplicationController" ||
		kind == "StatefulSet" ||
		kind == "DaemonSet" ||
		kind == "Job" ||
		kind == "CronJob"
}

// IsClusterScopedKind returns true if the specified kind is ClusterRole,
// ClusterRoleBinding, and CustomResourceDefinition.
//
// TODO Use discovery client to have a generic implementation.
func IsClusterScopedKind(kind string) bool {
	switch kind {
	case string(KindClusterRole), string(KindClusterRoleBindings), string(KindCustomResourceDefinition), string(KindPodSecurityPolicy):
		return true
	default:
		return false
	}
}

// ObjectRefToLabels encodes the specified ObjectRef as a set of labels.
//
// If Object's name cannot be used as the value of the
// starboard.LabelResourceName label, as a fallback, this method will calculate
// a hash of the Object's name and use it as the value of the
// starboard.LabelResourceNameHash label.
func ObjectRefToLabels(obj ObjectRef) map[string]string {
	labels := map[string]string{
		starboard.LabelResourceKind:      string(obj.Kind),
		starboard.LabelResourceNamespace: obj.Namespace,
	}
	if len(validation.IsValidLabelValue(obj.Name)) == 0 {
		labels[starboard.LabelResourceName] = obj.Name
	} else {
		labels[starboard.LabelResourceNameHash] = ComputeHash(obj.Name)
	}
	return labels
}

// ObjectToObjectMeta encodes the specified client.Object as a set of labels
// and annotations added to the given ObjectMeta.
func ObjectToObjectMeta(obj client.Object, meta *metav1.ObjectMeta) error {
	if meta.Labels == nil {
		meta.Labels = make(map[string]string)
	}
	meta.Labels[starboard.LabelResourceKind] = obj.GetObjectKind().GroupVersionKind().Kind
	meta.Labels[starboard.LabelResourceNamespace] = obj.GetNamespace()
	if len(validation.IsValidLabelValue(obj.GetName())) == 0 {
		meta.Labels[starboard.LabelResourceName] = obj.GetName()
	} else {
		meta.Labels[starboard.LabelResourceNameHash] = ComputeHash(obj.GetName())
		if meta.Annotations == nil {
			meta.Annotations = make(map[string]string)
		}
		meta.Annotations[starboard.LabelResourceName] = obj.GetName()
	}
	return nil
}

func ObjectRefFromObjectMeta(objectMeta metav1.ObjectMeta) (ObjectRef, error) {
	if _, found := objectMeta.Labels[starboard.LabelResourceKind]; !found {
		return ObjectRef{}, fmt.Errorf("required label does not exist: %s", starboard.LabelResourceKind)
	}
	var objname string
	if _, found := objectMeta.Labels[starboard.LabelResourceName]; !found {
		if _, found := objectMeta.Annotations[starboard.LabelResourceName]; found {
			objname = objectMeta.Annotations[starboard.LabelResourceName]
		} else {
			return ObjectRef{}, fmt.Errorf("required label does not exist: %s", starboard.LabelResourceName)
		}
	} else {
		objname = objectMeta.Labels[starboard.LabelResourceName]
	}
	return ObjectRef{
		Kind:      Kind(objectMeta.Labels[starboard.LabelResourceKind]),
		Name:      objname,
		Namespace: objectMeta.Labels[starboard.LabelResourceNamespace],
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

// ContainerImages is a simple structure to hold the mapping between container
// names and container image references.
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

func ObjectRefFromKindAndObjectKey(kind Kind, name client.ObjectKey) ObjectRef {
	return ObjectRef{
		Kind:      kind,
		Name:      name.Name,
		Namespace: name.Namespace,
	}
}

// ComputeSpecHash computes hash of the specified K8s client.Object. The hash is
// used to indicate whether the client.Object should be rescanned or not by
// adding it as the starboard.LabelResourceSpecHash label to an instance of a
// security report.
func ComputeSpecHash(obj client.Object) (string, error) {
	switch t := obj.(type) {
	case *corev1.Pod, *appsv1.Deployment, *appsv1.ReplicaSet, *corev1.ReplicationController, *appsv1.StatefulSet, *appsv1.DaemonSet, *batchv1.CronJob, *batchv1beta1.CronJob, *batchv1.Job:
		spec, err := GetPodSpec(obj)
		if err != nil {
			return "", err
		}
		return ComputeHash(spec), nil
	case *corev1.Service:
		return ComputeHash(obj), nil
	case *corev1.ConfigMap:
		return ComputeHash(obj), nil
	case *rbacv1.Role:
		return ComputeHash(obj), nil
	case *rbacv1.RoleBinding:
		return ComputeHash(obj), nil
	case *networkingv1.NetworkPolicy:
		return ComputeHash(obj), nil
	case *networkingv1.Ingress:
		return ComputeHash(obj), nil
	case *corev1.ResourceQuota:
		return ComputeHash(obj), nil
	case *corev1.LimitRange:
		return ComputeHash(obj), nil
	case *rbacv1.ClusterRole:
		return ComputeHash(obj), nil
	case *rbacv1.ClusterRoleBinding:
		return ComputeHash(obj), nil
	case *apiextensionsv1.CustomResourceDefinition:
		return ComputeHash(obj), nil
	default:
		return "", fmt.Errorf("computing spec hash of unsupported object: %T", t)
	}
}

// GetPodSpec returns v1.PodSpec from the specified Kubernetes client.Object.
// Returns error if the given client.Object is not a Kubernetes workload.
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
	case *batchv1.CronJob:
		return (obj.(*batchv1.CronJob)).Spec.JobTemplate.Spec.Template.Spec, nil
	case *batchv1.Job:
		return (obj.(*batchv1.Job)).Spec.Template.Spec, nil
	default:
		return corev1.PodSpec{}, fmt.Errorf("unsupported workload: %T", t)
	}
}

var ErrReplicaSetNotFound = errors.New("replicaset not found")
var ErrNoRunningPods = errors.New("no active pods for controller")
var ErrUnSupportedKind = errors.New("unsupported workload kind")

// CompatibleMgr provide k8s compatible objects (group/api/kind) capabilities
type CompatibleMgr interface {
	// GetSupportedObjectByKind get specific k8s compatible object (group/api/kind) by kind
	GetSupportedObjectByKind(kind Kind) client.Object
}

type CompatibleObjectMapper struct {
	kindObjectMap map[string]client.Object
}

type ObjectResolver struct {
	client.Client
	CompatibleMgr
}

func NewObjectResolver(c client.Client, cm CompatibleMgr) ObjectResolver {
	return ObjectResolver{c, cm}
}

// InitCompatibleMgr This initializes a CompatibleObjectMapper who store a map the of supported kinds with it compatible Objects (group/api/kind)
// it dynamically fetches the compatible k8ms objects (group/api/kind) by resource from the cluster and store it in kind vs k8s object mapping
// It will enable the operator to support old and new API resources based on cluster version support
func InitCompatibleMgr(restMapper meta.RESTMapper) (CompatibleMgr, error) {
	kindObjectMap := make(map[string]client.Object)
	for _, resource := range getCompatibleResources() {
		gvk, err := getGroupVersionKind(restMapper, resource)
		if err != nil {
			return nil, err
		}
		err = supportedObjectsByK8sKind(gvk.String(), gvk.Kind, kindObjectMap)
		if err != nil {
			return nil, err
		}
	}
	return &CompatibleObjectMapper{kindObjectMap: kindObjectMap}, nil
}

func getGroupVersionKind(restMapper meta.RESTMapper, resource string) (schema.GroupVersionKind, error) {
	// Special handling for CronJob
	if resource == "cronjobs" {
		if gvk, err := restMapper.KindFor(schema.GroupVersionResource{Group: "batch", Resource: resource, Version: "v1"}); err == nil {
			return gvk, nil
		}
		if gvk, err := restMapper.KindFor(schema.GroupVersionResource{Group: "batch", Resource: resource, Version: "v1beta1"}); err == nil {
			return gvk, nil
		}
		return schema.GroupVersionKind{}, fmt.Errorf("resource %s not found", resource)
	}

	// Special handling for Ingress
	if resource == "ingress" || resource == "ingresses" {
		if gvk, err := restMapper.KindFor(schema.GroupVersionResource{Group: "networking.k8s.io", Resource: "ingresses", Version: "v1"}); err == nil {
			return gvk, nil
		}
		if gvk, err := restMapper.KindFor(schema.GroupVersionResource{Group: "networking.k8s.io", Resource: "ingresses", Version: "v1beta1"}); err == nil {
			return gvk, nil
		}
		if gvk, err := restMapper.KindFor(schema.GroupVersionResource{Group: "extensions", Resource: "ingresses", Version: "v1beta1"}); err == nil {
			return gvk, nil
		}
		return schema.GroupVersionKind{}, fmt.Errorf("resource %s not found", resource)
	}

	// Default handling for other resources
	gvk, err := restMapper.KindFor(schema.GroupVersionResource{Resource: resource})
	if err != nil {
		return schema.GroupVersionKind{}, err
	}
	return gvk, nil
}

// return a map of supported object api per k8s version
func supportedObjectsByK8sKind(api string, kind string, kindObjectMap map[string]client.Object) error {
	var resource client.Object
	switch api {
	case apiBatchV1beta1CronJob:
		resource = &batchv1beta1.CronJob{}
	case apiBatchV1CronJob:
		resource = &batchv1.CronJob{}
	case apiNetworkV1betaIngress:
		resource = &networkingbetav1.Ingress{}
	case apiNetworkV1Ingress:
		resource = &networkingv1.Ingress{}
	case apiExtensionV1betaIngress:
		resource = &extensionv1beta1.Ingress{}
	default:
		return fmt.Errorf("api %s is not suooprted compatibale resource", api)
	}
	kindObjectMap[kind] = resource
	return nil
}

func getCompatibleResources() []string {
	return []string{cronJobResource, ingressResource}
}

// GetSupportedObjectByKind accept kind and return the supported object (group/api/kind) of the cluster
func (o *CompatibleObjectMapper) GetSupportedObjectByKind(kind Kind) client.Object {
	return o.kindObjectMap[string(kind)]
}

func (o *ObjectResolver) ObjectFromObjectRef(ctx context.Context, ref ObjectRef) (client.Object, error) {
	var obj client.Object
	switch ref.Kind {
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
		obj = o.CompatibleMgr.GetSupportedObjectByKind(KindCronJob)
	case KindJob:
		obj = &batchv1.Job{}
	case KindService:
		obj = &corev1.Service{}
	case KindConfigMap:
		obj = &metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
		}
	case KindRole:
		obj = &rbacv1.Role{}
	case KindRoleBinding:
		obj = &rbacv1.RoleBinding{}
	case KindNetworkPolicy:
		obj = &networkingv1.NetworkPolicy{}
	case KindIngress:
		obj = &networkingv1.Ingress{}
	case KindResourceQuota:
		obj = &corev1.ResourceQuota{}
	case KindLimitRange:
		obj = &corev1.LimitRange{}
	case KindClusterRole:
		obj = &rbacv1.ClusterRole{}
	case KindClusterRoleBindings:
		obj = &rbacv1.ClusterRoleBinding{}
	case KindCustomResourceDefinition:
		obj = &apiextensionsv1.CustomResourceDefinition{}
	case KindDeploymentConfig:
		obj = &ocpappsv1.DeploymentConfig{}
	default:
		return nil, fmt.Errorf("unknown kind: %s", ref.Kind)
	}
	err := o.Client.Get(ctx, client.ObjectKey{
		Name:      ref.Name,
		Namespace: ref.Namespace,
	}, obj)
	if err != nil {
		return nil, err
	}
	return o.ensureGVK(obj)
}

// ReportOwner resolves the owner of a security report for the specified object.
func (o *ObjectResolver) ReportOwner(ctx context.Context, obj client.Object) (client.Object, error) {
	switch obj.(type) {
	case *appsv1.Deployment:
		return o.ReplicaSetByDeployment(ctx, obj.(*appsv1.Deployment))
	case *batchv1.Job:
		controller := metav1.GetControllerOf(obj)
		if controller == nil {
			// Unmanaged Job
			return obj, nil
		}
		if controller.Kind == string(KindCronJob) {
			return o.CronJobByJob(ctx, obj.(*batchv1.Job))
		}
		// Job controlled by sth else (usually frameworks)
		return obj, nil
	case *corev1.Pod:
		controller := metav1.GetControllerOf(obj)
		if controller == nil {
			// Unmanaged Pod
			return obj, nil
		}
		if controller.Kind == string(KindReplicaSet) {
			return o.ReplicaSetByPod(ctx, obj.(*corev1.Pod))
		}
		if controller.Kind == string(KindJob) {
			// Managed by Job or CronJob
			job, err := o.JobByPod(ctx, obj.(*corev1.Pod))
			if err != nil {
				return nil, err
			}
			return o.ReportOwner(ctx, job)
		}
		// Pod controlled by sth else (usually frameworks)
		return obj, nil
	case *appsv1.ReplicaSet, *corev1.ReplicationController, *appsv1.StatefulSet, *appsv1.DaemonSet, *batchv1beta1.CronJob, *batchv1.CronJob:
		return obj, nil
	default:
		return obj, nil
	}
}

// ReplicaSetByDeploymentRef returns the current revision of the specified
// Deployment reference. If the current revision cannot be found the
// ErrReplicaSetNotFound error is returned.
func (o *ObjectResolver) ReplicaSetByDeploymentRef(ctx context.Context, deploymentRef ObjectRef) (*appsv1.ReplicaSet, error) {
	deployment := &appsv1.Deployment{}
	err := o.Client.Get(ctx, client.ObjectKey{
		Namespace: deploymentRef.Namespace,
		Name:      deploymentRef.Name,
	}, deployment)
	if err != nil {
		return nil, fmt.Errorf("getting deployment %q: %w", deploymentRef.Namespace+"/"+deploymentRef.Name, err)
	}
	return o.ReplicaSetByDeployment(ctx, deployment)
}

// ReplicaSetByDeployment returns the current revision of the specified
// Deployment. If the current revision cannot be found the ErrReplicaSetNotFound
// error is returned.
func (o *ObjectResolver) ReplicaSetByDeployment(ctx context.Context, deployment *appsv1.Deployment) (*appsv1.ReplicaSet, error) {
	var rsList appsv1.ReplicaSetList
	err := o.Client.List(ctx, &rsList,
		client.InNamespace(deployment.Namespace),
		client.MatchingLabelsSelector{
			Selector: labels.SelectorFromSet(deployment.Spec.Selector.MatchLabels),
		})
	if err != nil {
		return nil, fmt.Errorf("listing replicasets for deployment %q: %w", deployment.Namespace+"/"+deployment.Name, err)
	}

	if len(rsList.Items) == 0 {
		return nil, ErrReplicaSetNotFound
	}

	for _, rs := range rsList.Items {
		if deployment.Annotations[deploymentAnnotation] !=
			rs.Annotations[deploymentAnnotation] {
			continue
		}
		rsCopy := rs.DeepCopy()
		_, err = o.ensureGVK(rsCopy)
		return rsCopy, err
	}

	return nil, ErrReplicaSetNotFound
}

// ReplicaSetByPodRef returns the controller ReplicaSet of the specified Pod
// reference.
func (o *ObjectResolver) ReplicaSetByPodRef(ctx context.Context, object ObjectRef) (*appsv1.ReplicaSet, error) {
	pod := &corev1.Pod{}
	err := o.Client.Get(ctx, client.ObjectKey{
		Namespace: object.Namespace,
		Name:      object.Name,
	}, pod)
	if err != nil {
		return nil, err
	}
	return o.ReplicaSetByPod(ctx, pod)
}

// ReplicaSetByPod returns the controller ReplicaSet of the specified Pod.
func (o *ObjectResolver) ReplicaSetByPod(ctx context.Context, pod *corev1.Pod) (*appsv1.ReplicaSet, error) {
	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return nil, fmt.Errorf("did not find a controller for pod %q", pod.Namespace+"/"+pod.Name)
	}
	if controller.Kind != "ReplicaSet" {
		return nil, fmt.Errorf("pod %q is controlled by a %q, want replicaset", pod.Name, controller.Kind)
	}
	rs := &appsv1.ReplicaSet{}
	err := o.Client.Get(ctx, client.ObjectKey{
		Namespace: pod.Namespace,
		Name:      controller.Name,
	}, rs)
	if err != nil {
		return nil, err
	}
	rsCopy := rs.DeepCopy()
	_, err = o.ensureGVK(rsCopy)
	return rsCopy, err
}

func (o *ObjectResolver) CronJobByJob(ctx context.Context, job *batchv1.Job) (client.Object, error) {
	controller := metav1.GetControllerOf(job)
	if controller == nil {
		return nil, fmt.Errorf("did not find a controller for job %q", job.Name)
	}
	if controller.Kind != "CronJob" {
		return nil, fmt.Errorf("pod %q is controlled by a %q, want CronJob", job.Name, controller.Kind)
	}
	cj := o.CompatibleMgr.GetSupportedObjectByKind(KindCronJob)
	err := o.Client.Get(ctx, client.ObjectKey{Namespace: job.Namespace, Name: controller.Name}, cj)
	if err != nil {
		return nil, err
	}
	obj, err := o.ensureGVK(cj)
	return obj, err
}

func (o *ObjectResolver) JobByPod(ctx context.Context, pod *corev1.Pod) (*batchv1.Job, error) {
	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return nil, fmt.Errorf("did not find a controller for pod %q", pod.Name)
	}
	if controller.Kind != "Job" {
		return nil, fmt.Errorf("pod %q is controlled by a %q, want replicaset", pod.Name, controller.Kind)
	}
	rs := &batchv1.Job{}
	err := o.Client.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: controller.Name}, rs)
	if err != nil {
		return nil, err
	}
	obj, err := o.ensureGVK(rs)
	return obj.(*batchv1.Job), err
}

func (o *ObjectResolver) ensureGVK(obj client.Object) (client.Object, error) {
	gvk, err := apiutil.GVKForObject(obj, o.Client.Scheme())
	if err != nil {
		return nil, err
	}
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	return obj, nil
}

// RelatedReplicaSetName attempts to find the replicaset that is associated with
// the given owner. If the owner is a Deployment, it will look for a ReplicaSet
// that is controlled by the Deployment. If the owner is a Pod, it will look for
// the ReplicaSet that owns the Pod.
func (o *ObjectResolver) RelatedReplicaSetName(ctx context.Context, object ObjectRef) (string, error) {
	switch object.Kind {
	case KindDeployment:
		rs, err := o.ReplicaSetByDeploymentRef(ctx, object)
		if err != nil {
			return "", err
		}
		return rs.Name, nil
	case KindPod:
		rs, err := o.ReplicaSetByPodRef(ctx, object)
		if err != nil {
			return "", err
		}
		return rs.Name, nil
	}
	return "", fmt.Errorf("can only get related ReplicaSet for Deployment or Pod, not %q", string(object.Kind))
}

// GetNodeName returns the name of the node on which the given workload is
// scheduled. If there are no running pods then the ErrNoRunningPods error is
// returned. If there are no active ReplicaSets for the Deployment the
// ErrReplicaSetNotFound error is returned. If the specified workload is a
// CronJob the ErrUnSupportedKind error is returned.
func (o *ObjectResolver) GetNodeName(ctx context.Context, obj client.Object) (string, error) {
	switch obj.(type) {
	case *corev1.Pod:
		return (obj.(*corev1.Pod)).Spec.NodeName, nil
	case *appsv1.Deployment:
		replicaSet, err := o.ReplicaSetByDeployment(ctx, obj.(*appsv1.Deployment))
		if err != nil {
			return "", err
		}
		pods, err := o.getActivePodsByLabelSelector(ctx, obj.GetNamespace(), replicaSet.Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *appsv1.ReplicaSet:
		pods, err := o.getActivePodsByLabelSelector(ctx, obj.GetNamespace(), obj.(*appsv1.ReplicaSet).Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *corev1.ReplicationController:
		pods, err := o.getActivePodsByLabelSelector(ctx, obj.GetNamespace(), obj.(*corev1.ReplicationController).Spec.Selector)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *appsv1.StatefulSet:
		pods, err := o.getActivePodsByLabelSelector(ctx, obj.GetNamespace(), obj.(*appsv1.StatefulSet).Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *appsv1.DaemonSet:
		pods, err := o.getActivePodsByLabelSelector(ctx, obj.GetNamespace(), obj.(*appsv1.DaemonSet).Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *batchv1beta1.CronJob:
		return "", ErrUnSupportedKind
	case *batchv1.CronJob:
		return "", ErrUnSupportedKind
	case *batchv1.Job:
		pods, err := o.getActivePodsByLabelSelector(ctx, obj.GetNamespace(), obj.(*batchv1.Job).Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	default:
		return "", ErrUnSupportedKind
	}
}

func (o *ObjectResolver) IsActiveReplicaSet(ctx context.Context, workloadObj client.Object, controller *metav1.OwnerReference) (bool, error) {
	if controller != nil && controller.Kind == string(KindDeployment) {
		deploymentObject := &appsv1.Deployment{}

		err := o.Client.Get(ctx, client.ObjectKey{
			Namespace: workloadObj.GetNamespace(),
			Name:      controller.Name,
		}, deploymentObject)
		if err != nil {
			return false, err
		}
		deploymentRevisionAnnotation := deploymentObject.GetAnnotations()
		replicasetRevisionAnnotation := workloadObj.GetAnnotations()
		return replicasetRevisionAnnotation[deploymentAnnotation] == deploymentRevisionAnnotation[deploymentAnnotation], nil
	}
	return true, nil
}

func (o *ObjectResolver) IsActiveReplicationController(ctx context.Context, workloadObj client.Object, controller *metav1.OwnerReference) (bool, error) {
	if controller != nil && controller.Kind == string(KindDeploymentConfig) {
		deploymentConfigObj := &ocpappsv1.DeploymentConfig{}

		err := o.Client.Get(ctx, client.ObjectKey{
			Namespace: workloadObj.GetNamespace(),
			Name:      controller.Name,
		}, deploymentConfigObj)

		if err != nil {
			return false, err
		}
		replicasetRevisionAnnotation := workloadObj.GetAnnotations()
		latestRevision := fmt.Sprintf("%d", deploymentConfigObj.Status.LatestVersion)
		return replicasetRevisionAnnotation[deploymentConfigAnnotation] == latestRevision, nil
	}
	return true, nil
}

func (o *ObjectResolver) GetPodsByLabelSelector(ctx context.Context, namespace string,
	labelSelector labels.Set) ([]corev1.Pod, error) {
	podList := &corev1.PodList{}
	err := o.Client.List(ctx, podList, client.InNamespace(namespace),
		client.MatchingLabelsSelector{Selector: labels.SelectorFromSet(labelSelector)})
	if err != nil {
		return podList.Items, fmt.Errorf("listing pods in namespace %s for labelselector %v: %w", namespace,
			labelSelector, err)
	}
	return podList.Items, err
}

func (o *ObjectResolver) getActivePodsByLabelSelector(ctx context.Context, namespace string,
	labelSelector labels.Set) ([]corev1.Pod, error) {
	pods, err := o.GetPodsByLabelSelector(ctx, namespace, labelSelector)
	if err != nil {
		return pods, err
	}
	if len(pods) == 0 {
		return pods, ErrNoRunningPods
	}
	return pods, nil
}
