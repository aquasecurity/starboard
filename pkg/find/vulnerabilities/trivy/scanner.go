package trivy

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"io"

	"github.com/aquasecurity/starboard/pkg/docker"
	"github.com/aquasecurity/starboard/pkg/kube/secrets"
	"github.com/aquasecurity/starboard/pkg/scanners"
	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/google/uuid"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"
)

type Config interface {
	GetTrivyImageRef() string
}

// NewScanner constructs a new vulnerability Scanner with the specified options and Kubernetes client Interface.
func NewScanner(config Config, opts kube.ScannerOpts, clientset kubernetes.Interface) *Scanner {
	return &Scanner{
		config:    config,
		opts:      opts,
		clientset: clientset,
		pods:      pod.NewPodManager(clientset),
		converter: DefaultConverter,
	}
}

type Scanner struct {
	config    Config
	opts      kube.ScannerOpts
	clientset kubernetes.Interface
	pods      *pod.Manager
	converter Converter
}

func (s *Scanner) Scan(ctx context.Context, workload kube.Object) (reports vulnerabilities.WorkloadVulnerabilities, owner meta.Object, err error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)
	podSpec, owner, err := s.pods.GetPodSpecByWorkload(ctx, workload)
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

func (s *Scanner) ScanByPodSpec(ctx context.Context, workload kube.Object, spec core.PodSpec) (map[string]sec.VulnerabilityScanResult, error) {
	klog.V(3).Infof("Scanning with options: %+v", s.opts)

	imagePullSecrets, err := s.pods.GetImagePullSecrets(ctx, workload.Namespace, spec)
	if err != nil {
		return nil, err
	}

	auths, err := secrets.MapContainerImagesToAuths(spec, imagePullSecrets)
	if err != nil {
		return nil, err
	}

	job, imagePullSecret, err := s.PrepareScanJob(ctx, workload, spec, auths)
	if err != nil {
		return nil, fmt.Errorf("preparing scan job: %w", err)
	}

	if imagePullSecret != nil {
		klog.V(3).Infof("Creating image pull secret: %s/%s", starboard.NamespaceName, imagePullSecret.Name)
		_, err = s.clientset.CoreV1().Secrets(starboard.NamespaceName).Create(ctx, imagePullSecret, meta.CreateOptions{})
		if err != nil {
			return nil, err
		}
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

		if imagePullSecret != nil {
			klog.V(3).Infof("Deleting image pull secret: %s/%s", imagePullSecret.Namespace, imagePullSecret.Name)
			_ = s.clientset.CoreV1().Secrets(imagePullSecret.Namespace).Delete(ctx, imagePullSecret.Name, meta.DeleteOptions{})
		}
	}()

	klog.V(3).Infof("Scan job completed: %s/%s", job.Namespace, job.Name)

	job, err = s.clientset.BatchV1().Jobs(job.Namespace).Get(ctx, job.Name, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting scan job: %w", err)
	}

	return s.GetVulnerabilityReportsByScanJob(ctx, job)
}

func (s *Scanner) PrepareScanJob(_ context.Context, workload kube.Object, spec core.PodSpec, credentials map[string]docker.Auth) (*batch.Job, *core.Secret, error) {
	jobName := fmt.Sprintf(uuid.New().String())

	initContainerName := jobName
	imagePullSecretName := jobName
	imagePullSecretData := make(map[string][]byte)
	var imagePullSecret *core.Secret

	initContainers := []core.Container{
		{
			Name:                     initContainerName,
			Image:                    s.config.GetTrivyImageRef(),
			ImagePullPolicy:          core.PullIfNotPresent,
			TerminationMessagePolicy: core.TerminationMessageFallbackToLogsOnError,
			Env: []core.EnvVar{
				{
					Name: "HTTP_PROXY",
					ValueFrom: &core.EnvVarSource{
						ConfigMapKeyRef: &core.ConfigMapKeySelector{
							LocalObjectReference: core.LocalObjectReference{
								Name: starboard.ConfigMapName,
							},
							Key:      "trivy.httpProxy",
							Optional: pointer.BoolPtr(true),
						},
					},
				},
				{
					Name: "GITHUB_TOKEN",
					ValueFrom: &core.EnvVarSource{
						ConfigMapKeyRef: &core.ConfigMapKeySelector{
							LocalObjectReference: core.LocalObjectReference{
								Name: starboard.ConfigMapName,
							},
							Key:      "trivy.githubToken",
							Optional: pointer.BoolPtr(true),
						},
					},
				},
			},
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

	containerImages := kube.ContainerImages{}

	scanJobContainers := make([]core.Container, len(spec.Containers))
	for i, c := range spec.Containers {
		containerImages[c.Name] = c.Image

		var envs []core.EnvVar

		envs = append(envs,
			core.EnvVar{
				Name: "TRIVY_SEVERITY",
				ValueFrom: &core.EnvVarSource{
					ConfigMapKeyRef: &core.ConfigMapKeySelector{
						LocalObjectReference: core.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.severity",
						Optional: pointer.BoolPtr(true),
					},
				},
			}, core.EnvVar{
				Name: "HTTP_PROXY",
				ValueFrom: &core.EnvVarSource{
					ConfigMapKeyRef: &core.ConfigMapKeySelector{
						LocalObjectReference: core.LocalObjectReference{
							Name: starboard.ConfigMapName,
						},
						Key:      "trivy.httpProxy",
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		)

		if dockerConfig, ok := credentials[c.Image]; ok {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)

			imagePullSecretData[registryUsernameKey] = []byte(dockerConfig.Username)
			imagePullSecretData[registryPasswordKey] = []byte(dockerConfig.Password)

			envs = append(envs, core.EnvVar{
				Name: "TRIVY_USERNAME",
				ValueFrom: &core.EnvVarSource{
					SecretKeyRef: &core.SecretKeySelector{
						LocalObjectReference: core.LocalObjectReference{
							Name: imagePullSecretName,
						},
						Key: registryUsernameKey,
					},
				},
			}, core.EnvVar{
				Name: "TRIVY_PASSWORD",
				ValueFrom: &core.EnvVarSource{
					SecretKeyRef: &core.SecretKeySelector{
						LocalObjectReference: core.LocalObjectReference{
							Name: imagePullSecretName,
						},
						Key: registryPasswordKey,
					},
				},
			})
		}

		scanJobContainers[i] = core.Container{
			Name:                     c.Name,
			Image:                    s.config.GetTrivyImageRef(),
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
			Resources: core.ResourceRequirements{
				Limits: core.ResourceList{
					core.ResourceCPU:    resource.MustParse("500m"),
					core.ResourceMemory: resource.MustParse("500M"),
				},
				Requests: core.ResourceList{
					core.ResourceCPU:    resource.MustParse("100m"),
					core.ResourceMemory: resource.MustParse("100M"),
				},
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

	containerImagesAsJSON, err := containerImages.AsJSON()
	if err != nil {
		return nil, nil, err
	}

	if len(imagePullSecretData) > 0 {
		imagePullSecret = &core.Secret{
			ObjectMeta: meta.ObjectMeta{
				Name:      imagePullSecretName,
				Namespace: starboard.NamespaceName,
				Labels: map[string]string{
					kube.LabelResourceKind:      string(workload.Kind),
					kube.LabelResourceName:      workload.Name,
					kube.LabelResourceNamespace: workload.Namespace,
				},
			},
			Data: imagePullSecretData,
		}
	}

	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      jobName,
			Namespace: starboard.NamespaceName,
			Labels: map[string]string{
				kube.LabelResourceKind:      string(workload.Kind),
				kube.LabelResourceName:      workload.Name,
				kube.LabelResourceNamespace: workload.Namespace,
			},
			Annotations: map[string]string{
				kube.AnnotationContainerImages: containerImagesAsJSON,
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind:      string(workload.Kind),
						kube.LabelResourceName:      workload.Name,
						kube.LabelResourceNamespace: workload.Namespace,
					},
				},
				Spec: core.PodSpec{
					ServiceAccountName: starboard.ServiceAccountName,
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
	}, imagePullSecret, nil
}

func (s *Scanner) GetVulnerabilityReportsByScanJob(ctx context.Context, job *batch.Job) (reports vulnerabilities.WorkloadVulnerabilities, err error) {
	reports = make(map[string]sec.VulnerabilityScanResult)

	var containerImagesAsJSON string
	var ok bool

	if containerImagesAsJSON, ok = job.Annotations[kube.AnnotationContainerImages]; !ok {
		err = fmt.Errorf("scan job does not have required annotation: %s", kube.AnnotationContainerImages)
		return

	}
	containerImages := kube.ContainerImages{}
	err = containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		err = fmt.Errorf("reading scan job annotation: %s: %w", kube.AnnotationContainerImages, err)
		return
	}

	for _, c := range job.Spec.Template.Spec.Containers {
		klog.V(3).Infof("Getting logs for %s container in job: %s/%s", c.Name, job.Namespace, job.Name)
		var logReader io.ReadCloser
		logReader, err = s.pods.GetContainerLogsByJob(ctx, job, c.Name)
		if err != nil {
			return
		}
		reports[c.Name], err = s.converter.Convert(s.config, containerImages[c.Name], logReader)
		_ = logReader.Close()
		if err != nil {
			return
		}
	}
	return
}
