package polaris

import (
	"fmt"
	"time"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"

	"k8s.io/utils/pointer"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"
	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/google/uuid"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	runnerTimeout = 90 * time.Second
	jobTimeout    = 60 * time.Second
)

const (
	polarisContainerName = "polaris"
	// TODO: The latest semver tagged image 0.6.0 doesn't return audit checks ?!
	polarisContainerImage = "quay.io/fairwinds/polaris:cfc0d213cd603793d8e36eecfb0def1579a34997"
	polarisConfigVolume   = "config-volume"
	polarisConfigMap      = "polaris-config"
)

type Scanner struct {
	clientset kubernetes.Interface
	pods      *pod.Manager
	converter Converter
}

func NewScanner(config *rest.Config) (*Scanner, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &Scanner{
		clientset: clientset,
		pods:      pod.NewPodManager(clientset),
		converter: DefaultConverter,
	}, nil
}

func (s *Scanner) Scan() (reports []sec.ConfigAudit, err error) {
	polarisJob := s.preparePolarisJob()

	err = runner.New(runnerTimeout).
		Run(kube.NewRunnableJob(s.clientset, polarisJob))
	if err != nil {
		err = fmt.Errorf("running polaris job: %w", err)
		return
	}

	defer func() {
		klog.V(3).Infof("Deleting job: %s/%s", polarisJob.Namespace, polarisJob.Name)
		background := meta.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(polarisJob.Namespace).Delete(polarisJob.Name, &meta.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", polarisContainerName,
		polarisJob.Namespace, polarisJob.Name)
	logsReader, err := s.pods.GetPodLogsByJob(polarisJob, polarisContainerName)
	if err != nil {
		err = fmt.Errorf("getting logs: %w", err)
		return
	}

	reports, err = s.converter.Convert(logsReader)
	defer func() {
		_ = logsReader.Close()
	}()
	return
}

func (s *Scanner) preparePolarisJob() *batch.Job {
	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: kube.NamespaceStarboard,
			Labels: map[string]string{
				"app": "polaris",
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(1),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: pointer.Int64Ptr(int64(jobTimeout.Seconds())),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{
						"app": "polaris",
					},
				},
				Spec: core.PodSpec{
					ServiceAccountName: "starboard",
					RestartPolicy:      core.RestartPolicyNever,
					Volumes: []core.Volume{
						{
							Name: polarisConfigVolume,
							VolumeSource: core.VolumeSource{
								ConfigMap: &core.ConfigMapVolumeSource{
									LocalObjectReference: core.LocalObjectReference{
										Name: polarisConfigMap,
									},
								},
							},
						},
					},
					Containers: []core.Container{
						{
							Name:            polarisContainerName,
							Image:           polarisContainerImage,
							ImagePullPolicy: core.PullIfNotPresent,
							VolumeMounts: []core.VolumeMount{
								{
									Name:      polarisConfigVolume,
									MountPath: "/examples",
								},
							},
							Command: []string{"polaris"},
							Args:    []string{"audit", "--log-level", "error"},
						},
					},
				},
			},
		},
	}
}
