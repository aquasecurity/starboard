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
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"
)

const (
	kubeHunterContainerName  = "kube-hunter"
	kubeHunterContainerImage = "aquasec/kube-hunter:latest"
)

type Scanner struct {
	opts      kube.ScannerOpts
	clientset kubernetes.Interface
	pods      *pod.Manager
	scanners.Base
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
	kubeHunterJob := s.prepareKubeHunterJob()

	// 2. Run the prepared Job and wait for its completion or failure
	err = runner.New().Run(ctx, kube.NewRunnableJob(s.clientset, kubeHunterJob))
	if err != nil {
		err = fmt.Errorf("running kube-hunter job: %w", err)
		return
	}

	defer func() {
		// 5. Delete the kube-hunter Job
		klog.V(3).Infof("Deleting job: %s/%s", kubeHunterJob.Namespace, kubeHunterJob.Name)
		background := meta.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(kubeHunterJob.Namespace).Delete(ctx, kubeHunterJob.Name, meta.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	// 3. Get kube-hunter JSON output from the kube-hunter Pod
	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", kubeHunterContainerName,
		kubeHunterJob.Namespace, kubeHunterJob.Name)
	logsReader, err := s.pods.GetPodLogsByJob(ctx, kubeHunterJob, kubeHunterContainerName)
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
			BackoffLimit:          pointer.Int32Ptr(1),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: s.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: map[string]string{
						"app": "kube-hunter",
					},
				},
				Spec: core.PodSpec{
					RestartPolicy: core.RestartPolicyNever,
					HostPID:       true,
					Containers: []core.Container{
						{
							Name:            kubeHunterContainerName,
							Image:           kubeHunterContainerImage,
							ImagePullPolicy: core.PullAlways,
							Command:         []string{"python", "kube-hunter.py"},
							Args:            []string{"--pod", "--report", "json", "--log", "warn"},
						},
					},
				},
			},
		},
	}
}
