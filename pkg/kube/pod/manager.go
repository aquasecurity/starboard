package pod

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager struct {
	clientset kubernetes.Interface
}

func NewPodManager(clientset kubernetes.Interface) *Manager {
	return &Manager{
		clientset: clientset,
	}
}

// GetPodSpecByWorkload returns a PodSpec of the specified Workload.
func (pw *Manager) GetPodSpecByWorkload(ctx context.Context, workload kube.Object) (spec corev1.PodSpec, object client.Object, err error) {
	ns := workload.Namespace
	switch workload.Kind {
	case kube.KindPod:
		var pod *corev1.Pod
		pod, err = pw.clientset.CoreV1().Pods(ns).Get(ctx, workload.Name, metav1.GetOptions{})
		if err != nil {
			return
		}
		spec = pod.Spec
		object = pod
		return
	case kube.KindReplicaSet:
		var rs *appsv1.ReplicaSet
		rs, err = pw.clientset.AppsV1().ReplicaSets(ns).Get(ctx, workload.Name, metav1.GetOptions{})
		if err != nil {
			return
		}
		spec = rs.Spec.Template.Spec
		object = rs
		return
	case kube.KindReplicationController:
		var rc *corev1.ReplicationController
		rc, err = pw.clientset.CoreV1().ReplicationControllers(ns).Get(ctx, workload.Name, metav1.GetOptions{})
		if err != nil {
			return
		}
		spec = rc.Spec.Template.Spec
		object = rc
		return
	case kube.KindDeployment:
		var deploy *appsv1.Deployment
		deploy, err = pw.clientset.AppsV1().Deployments(ns).Get(ctx, workload.Name, metav1.GetOptions{})
		if err != nil {
			return
		}
		spec = deploy.Spec.Template.Spec
		object = deploy
		return
	case kube.KindStatefulSet:
		var sts *appsv1.StatefulSet
		sts, err = pw.clientset.AppsV1().StatefulSets(ns).Get(ctx, workload.Name, metav1.GetOptions{})
		if err != nil {
			return
		}
		spec = sts.Spec.Template.Spec
		object = sts
		return
	case kube.KindDaemonSet:
		var ds *appsv1.DaemonSet
		ds, err = pw.clientset.AppsV1().DaemonSets(ns).Get(ctx, workload.Name, metav1.GetOptions{})
		if err != nil {
			return
		}
		spec = ds.Spec.Template.Spec
		object = ds
		return
	case kube.KindCronJob:
		var cj *batchv1beta1.CronJob
		cj, err = pw.clientset.BatchV1beta1().CronJobs(ns).Get(ctx, workload.Name, metav1.GetOptions{})
		if err != nil {
			return
		}
		spec = cj.Spec.JobTemplate.Spec.Template.Spec
		object = cj
		return
	case kube.KindJob:
		var job *batchv1.Job
		job, err = pw.clientset.BatchV1().Jobs(ns).Get(ctx, workload.Name, metav1.GetOptions{})
		if err != nil {
			return
		}
		spec = job.Spec.Template.Spec
		object = job
		return
	}
	err = fmt.Errorf("unrecognized workload: %s", workload.Kind)
	return
}
