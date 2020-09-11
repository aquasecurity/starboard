package kubehunter

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/scanners"

	"k8s.io/klog"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/google/uuid"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"
)

const (
	kubeHunterVersion       = "0.3.1"
	kubeHunterContainerName = "kube-hunter"
)

var (
	kubeHunterContainerImage = fmt.Sprintf("aquasec/kube-hunter:%s", kubeHunterVersion)
)

type Scanner struct {
	opts      kube.ScannerOpts
	clientset kubernetes.Interface
	pods      *pod.Manager
}

func NewScanner(opts kube.ScannerOpts, clientset kubernetes.Interface) *Scanner {
	return &Scanner{
		opts:      opts,
		clientset: clientset,
		pods:      pod.NewPodManager(clientset),
	}
}

func (s *Scanner) Scan(ctx context.Context) (report starboard.KubeHunterOutput, err error) {
	// 1. Prepare descriptor for the Kubernetes Job which will run kube-hunter
	job := s.prepareKubeHunterJob()

	// 2. Run the prepared Job and wait for its completion or failure
	err = runner.New().Run(ctx, kube.NewRunnableJob(s.clientset, job))
	if err != nil {
		err = fmt.Errorf("running kube-hunter job: %w", err)
		return
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		// 5. Delete the kube-hunter Job
		klog.V(3).Infof("Deleting job: %s/%s", job.Namespace, job.Name)
		background := meta.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, meta.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	// 3. Get kube-hunter JSON output from the kube-hunter Pod
	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", kubeHunterContainerName,
		job.Namespace, job.Name)
	logsReader, err := s.pods.GetContainerLogsByJob(ctx, job, kubeHunterContainerName)
	if err != nil {
		err = fmt.Errorf("getting logs: %w", err)
		return
	}
	defer func() {
		_ = logsReader.Close()
	}()

	// 4. Parse the KubeHuberOutput from the logs Reader
	report, err = OutputFrom(logsReader)
	if err != nil {
		err = fmt.Errorf("parsing kube hunter report: %w", err)
		return
	}

	return
}

func (s *Scanner) prepareKubeHunterJob() *batch.Job {
	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: kube.NamespaceStarboard,
			Labels: map[string]string{
				"app": "kube-hunter",
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{
						"app": "kube-hunter",
					},
				},
				Spec: core.PodSpec{
					ServiceAccountName: kube.ServiceAccountStarboard,
					RestartPolicy:      core.RestartPolicyNever,
					HostPID:            true,
					Containers: []core.Container{
						{
							Name:                     kubeHunterContainerName,
							Image:                    kubeHunterContainerImage,
							ImagePullPolicy:          core.PullIfNotPresent,
							TerminationMessagePolicy: core.TerminationMessageFallbackToLogsOnError,
							Command:                  []string{"python", "kube-hunter.py"},
							Args:                     []string{"--pod", "--report", "json", "--log", "warn"},
							Resources: core.ResourceRequirements{
								Limits: core.ResourceList{
									core.ResourceCPU:    resource.MustParse("300m"),
									core.ResourceMemory: resource.MustParse("400M"),
								},
								Requests: core.ResourceList{
									core.ResourceCPU:    resource.MustParse("50m"),
									core.ResourceMemory: resource.MustParse("100M"),
								},
							},
						},
					},
				},
			},
		},
	}
}
