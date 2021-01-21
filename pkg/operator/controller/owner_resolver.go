package controller

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type OwnerResolver struct {
	client.Client
}

func (o *OwnerResolver) Resolve(ctx context.Context, workload kube.Object) (client.Object, error) {
	var obj client.Object
	switch workload.Kind {
	case kube.KindPod:
		obj = &corev1.Pod{}
	case kube.KindReplicaSet:
		obj = &appsv1.ReplicaSet{}
	case kube.KindReplicationController:
		obj = &corev1.ReplicationController{}
	case kube.KindDeployment:
		obj = &appsv1.Deployment{}
	case kube.KindStatefulSet:
		obj = &appsv1.StatefulSet{}
	case kube.KindDaemonSet:
		obj = &appsv1.DaemonSet{}
	case kube.KindCronJob:
		obj = &batchv1beta1.CronJob{}
	case kube.KindJob:
		obj = &batchv1.Job{}
	default:
		return nil, fmt.Errorf("unknown workload kind: %s", workload.Kind)
	}
	err := o.Client.Get(ctx, types.NamespacedName{Name: workload.Name, Namespace: workload.Namespace}, obj)
	if err != nil {
		return nil, err
	}
	return obj, nil
}
