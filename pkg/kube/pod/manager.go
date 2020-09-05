package pod

import (
	"context"
	"fmt"
	"io"

	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/kube"

	apps "k8s.io/api/apps/v1"
	batch "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	serviceAccountDefault = "default"
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
func (pw *Manager) GetPodSpecByWorkload(ctx context.Context, workload kube.Object) (spec core.PodSpec, object meta.Object, err error) {
	ns := workload.Namespace
	switch workload.Kind {
	case kube.KindPod:
		var pod *core.Pod
		pod, err = pw.GetPodByName(ctx, ns, workload.Name)
		if err != nil {
			return
		}
		spec = pod.Spec
		object = pod
		return
	case kube.KindReplicaSet:
		var rs *apps.ReplicaSet
		rs, err = pw.clientset.AppsV1().ReplicaSets(ns).Get(ctx, workload.Name, meta.GetOptions{})
		if err != nil {
			return
		}
		spec = rs.Spec.Template.Spec
		object = rs
		return
	case kube.KindReplicationController:
		var rc *core.ReplicationController
		rc, err = pw.clientset.CoreV1().ReplicationControllers(ns).Get(ctx, workload.Name, meta.GetOptions{})
		if err != nil {
			return
		}
		spec = rc.Spec.Template.Spec
		object = rc
		return
	case kube.KindDeployment:
		var deploy *apps.Deployment
		deploy, err = pw.clientset.AppsV1().Deployments(ns).Get(ctx, workload.Name, meta.GetOptions{})
		if err != nil {
			return
		}
		spec = deploy.Spec.Template.Spec
		object = deploy
		return
	case kube.KindStatefulSet:
		var sts *apps.StatefulSet
		sts, err = pw.clientset.AppsV1().StatefulSets(ns).Get(ctx, workload.Name, meta.GetOptions{})
		if err != nil {
			return
		}
		spec = sts.Spec.Template.Spec
		object = sts
		return
	case kube.KindDaemonSet:
		var ds *apps.DaemonSet
		ds, err = pw.clientset.AppsV1().DaemonSets(ns).Get(ctx, workload.Name, meta.GetOptions{})
		if err != nil {
			return
		}
		spec = ds.Spec.Template.Spec
		object = ds
		return
	case kube.KindCronJob:
		var cj *batchv1beta1.CronJob
		cj, err = pw.clientset.BatchV1beta1().CronJobs(ns).Get(ctx, workload.Name, meta.GetOptions{})
		if err != nil {
			return
		}
		spec = cj.Spec.JobTemplate.Spec.Template.Spec
		object = cj
		return
	case kube.KindJob:
		var job *batch.Job
		job, err = pw.clientset.BatchV1().Jobs(ns).Get(ctx, workload.Name, meta.GetOptions{})
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

// GetImagePullSecrets returns the union of image pull Secrets specified on the given PodSpec
// and image pull secrets added to the Service Account.
func (pw *Manager) GetImagePullSecrets(ctx context.Context, namespace string, spec core.PodSpec) ([]core.Secret, error) {
	secrets := make([]core.Secret, 0)

	for _, secretRef := range spec.ImagePullSecrets {
		secret, err := pw.clientset.CoreV1().Secrets(namespace).
			Get(ctx, secretRef.Name, meta.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("getting secret by name: %s/%s: %w", namespace, secretRef.Name, err)
		}
		secrets = append(secrets, *secret)
	}

	serviceAccountName := spec.ServiceAccountName
	// Note: For Kubernetes controllers the ServiceAccountName field might be blank.
	if serviceAccountName == "" {
		serviceAccountName = serviceAccountDefault
	}

	serviceAccount, err := pw.clientset.CoreV1().ServiceAccounts(namespace).
		Get(ctx, serviceAccountName, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting service account by name: %s/%s: %w", namespace, serviceAccountName, err)
	}

	for _, secretRef := range serviceAccount.ImagePullSecrets {
		secret, err := pw.clientset.CoreV1().Secrets(namespace).
			Get(ctx, secretRef.Name, meta.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("getting secret by name: %s/%s: %w", namespace, secretRef.Name, err)
		}
		secrets = append(secrets, *secret)
	}

	return secrets, nil
}

func (pw *Manager) GetPodByName(ctx context.Context, namespace, name string) (*core.Pod, error) {
	return pw.clientset.CoreV1().Pods(namespace).Get(ctx, name, meta.GetOptions{})
}

func (pw *Manager) GetTerminatedContainersStatusesByJob(ctx context.Context, job *batch.Job) (statuses map[string]*core.ContainerStateTerminated, err error) {
	pod, err := pw.GetPodByJob(ctx, job)
	if err != nil {
		return
	}
	statuses = pw.GetTerminatedContainersStatusesByPod(pod)
	return
}

func (pw *Manager) GetTerminatedContainersStatusesByPod(pod *core.Pod) map[string]*core.ContainerStateTerminated {
	states := make(map[string]*core.ContainerStateTerminated)
	for _, status := range pod.Status.InitContainerStatuses {
		if status.State.Terminated == nil {
			continue
		}
		states[status.Name] = status.State.Terminated
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.State.Terminated == nil {
			continue
		}
		states[status.Name] = status.State.Terminated
	}
	return states
}

func (pw *Manager) GetContainerLogsByJob(ctx context.Context, job *batch.Job, container string) (io.ReadCloser, error) {
	pod, err := pw.GetPodByJob(ctx, job)
	if err != nil {
		return nil, err
	}

	return pw.GetPodLogs(ctx, pod, container)
}

// GetPodByJob gets the Pod controller by the specified Job.
func (pw *Manager) GetPodByJob(ctx context.Context, job *batch.Job) (*core.Pod, error) {
	refreshedJob, err := pw.clientset.BatchV1().Jobs(job.Namespace).Get(ctx, job.Name, meta.GetOptions{})
	if err != nil {
		return nil, err
	}
	selector := fmt.Sprintf("controller-uid=%s", refreshedJob.Spec.Selector.MatchLabels["controller-uid"])
	podList, err := pw.clientset.CoreV1().Pods(job.Namespace).List(ctx, meta.ListOptions{
		LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	return &podList.Items[0], nil
}

func (pw *Manager) GetPodLogs(ctx context.Context, pod *core.Pod, container string) (io.ReadCloser, error) {
	req := pw.clientset.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &core.PodLogOptions{
		Follow: true, Container: container})
	return req.Stream(ctx)
}

// TODO Consider moving this generic code to kube.runnableJob and call it in case of failure
func (pw *Manager) LogRunnerErrors(ctx context.Context, job *batch.Job) {
	statuses, err := pw.GetTerminatedContainersStatusesByJob(ctx, job)
	if err != nil {
		klog.Errorf("Error while getting terminated containers statuses for scan job: %s/%s", job.Namespace, job.Name)
	} else {
		pw.logTerminatedContainersErrors(statuses)
	}
}

func (pw *Manager) logTerminatedContainersErrors(statuses map[string]*core.ContainerStateTerminated) {
	for container, status := range statuses {
		if status.ExitCode == 0 {
			continue
		}
		klog.Errorf("Container %s terminated with %s: %s", container, status.Reason, status.Message)
	}
}

// GetImages gets a slice of images for the specified PodSpec.
func GetImages(spec core.PodSpec) (images []string) {
	for _, c := range spec.InitContainers {
		images = append(images, c.Image)
	}

	for _, c := range spec.Containers {
		images = append(images, c.Image)
	}

	return
}
