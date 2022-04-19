package cmd

import (
	"context"
	"github.com/aquasecurity/starboard/pkg/kube"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	AppsGroup              = "apps"
	CoreGroup              = "cores"
	BatchGroup             = "batch"
	RbacGroup              = "rbac"
	NetworkingGroup        = "networking"
	PolicyGroup            = "policy"
	V1Version              = "v1"
	V1beta1Version         = "v1Beta1"
	Deployments            = "deployments"
	ReplicaSets            = "replicasets"
	ReplicationControllers = "replicationcontrollers"
	StatefulSets           = "statefulsets"
	DaemonSets             = "daemonsets"
	CronJobs               = "cronjobs"
	Services               = "services"
	Jobs                   = "jobs"
	Pods                   = "pods"
	ConfigMaps             = "configmaps"
	Roles                  = "roles"
	RoleBindings           = "rolebindings"
	ClusterRoles           = "clusterroles"
	ClusterRoleBindings    = "clusterrolebindings"
	NetworkPolicys         = "networkpolicy"
	Ingresss               = "ingresss"
	ResourceQuotas         = "resourceQuotas"
	LimitRanges            = "limitranges"
	PodSecurityPolicy      = "podsecuritypolicys"
)

func getNamespaceGVR() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: Deployments,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: Pods,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: ReplicaSets,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: ReplicationControllers,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: StatefulSets,
		},
		{
			Version:  V1Version,
			Group:    AppsGroup,
			Resource: DaemonSets,
		},
		{
			Version:  V1beta1Version,
			Group:    BatchGroup,
			Resource: CronJobs,
		},
		{
			Version:  V1Version,
			Group:    BatchGroup,
			Resource: Jobs,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: Services,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: ConfigMaps,
		},
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: Roles,
		},
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: RoleBindings,
		},
		{
			Version:  V1Version,
			Group:    NetworkingGroup,
			Resource: NetworkPolicys,
		},
		{
			Version:  V1Version,
			Group:    NetworkingGroup,
			Resource: Ingresss,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: ResourceQuotas,
		},
		{
			Version:  V1Version,
			Group:    CoreGroup,
			Resource: LimitRanges,
		},
	}
}

func getClusterGVR() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: ClusterRoles,
		},
		{
			Version:  V1Version,
			Group:    RbacGroup,
			Resource: ClusterRoleBindings,
		},
		{
			Version:  V1beta1Version,
			Group:    PolicyGroup,
			Resource: PodSecurityPolicy,
		},
	}
}

func getResources(ctx context.Context, client dynamic.Interface, namespace string, gvrs []schema.GroupVersionResource) ([]kube.ObjectRef, error) {
	ObjRefs := make([]kube.ObjectRef, 0)
	for _, gvr := range gvrs {
		var dclient dynamic.ResourceInterface
		if len(namespace) == 0 {
			dclient = client.Resource(gvr)
		} else {
			dclient = client.Resource(gvr).Namespace(namespace)
		}
		objectList, err := dclient.List(ctx, metav1.ListOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		for _, item := range objectList.Items {
			ObjRefs = append(ObjRefs, kube.ObjectRef{Namespace: namespace, Kind: kube.Kind(item.GetKind()), Name: item.GetName()})
		}
	}
	return ObjRefs, nil
}
