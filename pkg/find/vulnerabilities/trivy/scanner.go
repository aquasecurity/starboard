package trivy

import (
	"fmt"
	"github.com/aquasecurity/starboard/pkg/ext"
	"io"
	"time"

	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/aquasecurity/starboard/pkg/kube/secret"
	"github.com/google/uuid"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"
)

const (
	kubernetesNameMaxLength int = 63
)

const (
	trivyImageRef = "docker.io/aquasec/trivy:0.8.0"
)

var (
	scanJobRunnerTimeout = 60 * time.Second
)

type scanner struct {
	clientset kubernetes.Interface
	pods      *pod.Manager
	secrets   *secret.Manager
	converter Converter
}

func NewScanner(clientset kubernetes.Interface) vulnerabilities.Scanner {
	return &scanner{
		clientset: clientset,
		pods:      pod.NewPodManager(clientset),
		secrets:   secret.NewSecretManager(clientset),
		converter: DefaultConverter,
	}
}

func (s *scanner) Scan(workload kube.Workload) (reports map[string]sec.VulnerabilityReport, err error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)
	podSpec, err := s.pods.GetPodSpecByWorkload(workload)
	if err != nil {
		err = fmt.Errorf("getting Pod template: %w", err)
		return
	}

	reports, err = s.ScanByPodSpec(workload, podSpec)
	if err != nil {
		return
	}
	return
}

func (s *scanner) ScanByPodSpec(workload kube.Workload, spec core.PodSpec) (map[string]sec.VulnerabilityReport, error) {
	job, err := s.prepareJob(workload, spec)
	if err != nil {
		return nil, fmt.Errorf("preparing scan job: %w", err)
	}

	err = runner.New(scanJobRunnerTimeout).
		Run(kube.NewRunnableJob(s.clientset, job))
	if err != nil {
		return nil, fmt.Errorf("running scan job: %w", err)
	}

	defer func() {
		klog.V(3).Infof("Deleting job: %s/%s", job.Namespace, job.Name)
		background := meta.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(job.Name, &meta.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	klog.V(3).Infof("Scan job completed: %s/%s", job.Namespace, job.Name)

	job, err = s.clientset.BatchV1().Jobs(job.Namespace).Get(job.Name, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting scan job: %w", err)
	}

	return s.getScanReportsFor(job)
}

func (s *scanner) prepareJob(workload kube.Workload, spec core.PodSpec) (*batch.Job, error) {
	credentials, err := s.secrets.GetImagesWithCredentials(workload.Namespace, spec)
	if err != nil {
		return nil, fmt.Errorf("getting docker configs: %w", err)
	}

	jobName := fmt.Sprintf(uuid.New().String())
	jobName = jobName[:ext.MinInt(len(jobName), kubernetesNameMaxLength)]

	initContainers := []core.Container{
		{
			Name:            jobName,
			Image:           trivyImageRef,
			ImagePullPolicy: core.PullAlways,
			Command: []string{
				"trivy",
			},
			Args: []string{
				"--download-db-only",
				"--cache-dir",
				"/var/lib/trivy",
			},
			VolumeMounts: []core.VolumeMount{
				{
					Name:      "data",
					ReadOnly:  false,
					MountPath: "/var/lib/trivy",
				},
			},
		},
	}

	scanJobContainers := make([]core.Container, len(spec.Containers))
	for i, c := range spec.Containers {
		var envs []core.EnvVar
		if dockerConfig, ok := credentials[c.Image]; ok {
			envs = append(envs, core.EnvVar{
				Name:  "TRIVY_USERNAME",
				Value: dockerConfig.Username,
			}, core.EnvVar{
				Name:  "TRIVY_PASSWORD",
				Value: dockerConfig.Password,
			})
		}

		scanJobContainers[i] = core.Container{
			Name:            c.Name,
			Image:           trivyImageRef,
			ImagePullPolicy: core.PullAlways,
			Env:             envs,
			Command: []string{
				"trivy",
			},
			Args: []string{
				"--skip-update",
				"--cache-dir",
				"/var/lib/trivy",
				"--no-progress",
				"--quiet",
				"--format",
				"json",
				c.Image,
			},
			VolumeMounts: []core.VolumeMount{
				{
					Name:      "data",
					ReadOnly:  false,
					MountPath: "/var/lib/trivy",
				},
			},
		}
	}

	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      jobName,
			Namespace: kube.NamespaceStarboard,
			Labels: map[string]string{
				kube.LabelResourceKind: workload.Kind.String(),
				kube.LabelResourceName: workload.Name,
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(1),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: pointer.Int64Ptr(int64(scanJobRunnerTimeout.Seconds())),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind: workload.Kind.String(),
						kube.LabelResourceName: workload.Name,
					},
				},
				Spec: core.PodSpec{
					Volumes: []core.Volume{
						{
							Name: "data",
							VolumeSource: core.VolumeSource{
								EmptyDir: &core.EmptyDirVolumeSource{
									Medium: core.StorageMediumDefault,
								},
							},
						},
					},
					RestartPolicy:  core.RestartPolicyNever,
					InitContainers: initContainers,
					Containers:     scanJobContainers,
				},
			},
		},
	}, nil
}

func (s *scanner) getScanReportsFor(job *batch.Job) (reports map[string]sec.VulnerabilityReport, err error) {
	reports = make(map[string]sec.VulnerabilityReport)

	for _, c := range job.Spec.Template.Spec.Containers {
		klog.V(3).Infof("Getting logs for %s container in job: %s/%s", c.Name, job.Namespace, job.Name)
		var logReader io.ReadCloser
		logReader, err = s.pods.GetPodLogsByJob(job, c.Name)
		if err != nil {
			return
		}
		reports[c.Name], err = s.converter.Convert(logReader)
		_ = logReader.Close()
		if err != nil {
			return
		}
	}
	return
}
