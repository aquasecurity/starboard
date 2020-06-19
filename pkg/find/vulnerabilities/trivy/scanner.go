package trivy

import (
	"context"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/scanners"
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
	trivyVersion = "0.9.1"
)

var (
	trivyImageRef = fmt.Sprintf("docker.io/aquasec/trivy:%s", trivyVersion)
)

// NewScanner constructs a new vulnerability Scanner with the specified options and Kubernetes client Interface.
func NewScanner(opts kube.ScannerOpts, clientset kubernetes.Interface) vulnerabilities.Scanner {
	return &scanner{
		opts:      opts,
		clientset: clientset,
		pods:      pod.NewPodManager(clientset),
		secrets:   secret.NewSecretManager(clientset),
		converter: DefaultConverter,
	}
}

type scanner struct {
	opts      kube.ScannerOpts
	clientset kubernetes.Interface
	pods      *pod.Manager
	secrets   *secret.Manager
	converter Converter
	scanners.Base
}

func (s *scanner) Scan(ctx context.Context, workload kube.Workload) (reports map[string]sec.VulnerabilityReport, err error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)
	podSpec, err := s.pods.GetPodSpecByWorkload(ctx, workload)
	if err != nil {
		err = fmt.Errorf("getting Pod template: %w", err)
		return
	}

	reports, err = s.ScanByPodSpec(ctx, workload, podSpec)
	if err != nil {
		return
	}
	return
}

func (s *scanner) ScanByPodSpec(ctx context.Context, workload kube.Workload, spec core.PodSpec) (map[string]sec.VulnerabilityReport, error) {
	klog.V(3).Infof("Scanning with options: %+v", s.opts)
	job, err := s.prepareJob(ctx, workload, spec)
	if err != nil {
		return nil, fmt.Errorf("preparing scan job: %w", err)
	}

	err = runner.New().Run(ctx, kube.NewRunnableJob(s.clientset, job))
	if err != nil {
		s.pods.LogRunnerErrors(ctx, job)
		return nil, fmt.Errorf("running scan job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		klog.V(3).Infof("Deleting scan job: %s/%s", job.Namespace, job.Name)
		background := meta.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, meta.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	klog.V(3).Infof("Scan job completed: %s/%s", job.Namespace, job.Name)

	job, err = s.clientset.BatchV1().Jobs(job.Namespace).Get(ctx, job.Name, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting scan job: %w", err)
	}

	return s.getScanReportsFor(ctx, job)
}

func (s *scanner) prepareJob(ctx context.Context, workload kube.Workload, spec core.PodSpec) (*batch.Job, error) {
	credentials, err := s.secrets.GetImagesWithCredentials(ctx, workload.Namespace, spec)
	if err != nil {
		return nil, fmt.Errorf("getting docker configs: %w", err)
	}

	jobName := fmt.Sprintf(uuid.New().String())

	initContainers := []core.Container{
		{
			Name:                     jobName,
			Image:                    trivyImageRef,
			ImagePullPolicy:          core.PullIfNotPresent,
			TerminationMessagePolicy: core.TerminationMessageFallbackToLogsOnError,
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
			Name:                     c.Name,
			Image:                    trivyImageRef,
			ImagePullPolicy:          core.PullIfNotPresent,
			TerminationMessagePolicy: core.TerminationMessageFallbackToLogsOnError,
			Env:                      envs,
			Command: []string{
				"trivy",
			},
			Args: []string{
				"--skip-update",
				"--cache-dir",
				"/var/lib/trivy",
				"--no-progress",
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
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: s.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind: workload.Kind.String(),
						kube.LabelResourceName: workload.Name,
					},
				},
				Spec: core.PodSpec{
					AutomountServiceAccountToken: pointer.BoolPtr(false),
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

func (s *scanner) getScanReportsFor(ctx context.Context, job *batch.Job) (reports map[string]sec.VulnerabilityReport, err error) {
	reports = make(map[string]sec.VulnerabilityReport)

	for _, c := range job.Spec.Template.Spec.Containers {
		klog.V(3).Infof("Getting logs for %s container in job: %s/%s", c.Name, job.Namespace, job.Name)
		var logReader io.ReadCloser
		logReader, err = s.pods.GetContainerLogsByJob(ctx, job, c.Name)
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
