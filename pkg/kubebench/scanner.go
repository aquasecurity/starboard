package kubebench

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"

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
	"k8s.io/utils/pointer"

	"k8s.io/client-go/kubernetes"
)

const (
	kubeBenchVersion       = "0.3.1"
	kubeBenchContainerName = "kube-bench"
	masterNodeLabel        = "node-role.kubernetes.io/master"
)

var (
	kubeBenchContainerImage = fmt.Sprintf("aquasec/kube-bench:%s", kubeBenchVersion)
)

type Scanner struct {
	opts      kube.ScannerOpts
	clientset kubernetes.Interface
	pods      *pod.Manager
	converter Converter
}

func NewScanner(opts kube.ScannerOpts, clientset kubernetes.Interface) *Scanner {
	return &Scanner{
		opts:      opts,
		clientset: clientset,
		pods:      pod.NewPodManager(clientset),
		converter: DefaultConverter,
	}
}

func (s *Scanner) Scan(ctx context.Context, node core.Node) (report starboard.CISKubeBenchOutput, err error) {
	// 1. Prepare descriptor for the Kubernetes Job which will run kube-bench
	job := s.prepareKubeBenchJob(node)

	// 2. Run the prepared Job and wait for its completion or failure
	err = runner.New().Run(ctx, kube.NewRunnableJob(s.clientset, job))
	if err != nil {
		err = fmt.Errorf("running kube-bench job: %w", err)
		return
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		// 6. Delete the kube-bench Job
		klog.V(3).Infof("Deleting job: %s/%s", job.Namespace, job.Name)
		background := meta.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, meta.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	// 3. Get the Pod controlled by the kube-bench Job
	kubeBenchPod, err := s.pods.GetPodByJob(ctx, job)
	if err != nil {
		err = fmt.Errorf("getting kube-bench pod: %w", err)
		return
	}

	// 4. Get kube-bench JSON output from the kube-bench Pod
	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", kubeBenchContainerName,
		job.Namespace, job.Name)
	logsReader, err := s.pods.GetPodLogs(ctx, kubeBenchPod, kubeBenchContainerName)
	if err != nil {
		err = fmt.Errorf("getting logs: %w", err)
		return
	}
	defer func() {
		_ = logsReader.Close()
	}()

	// 5. Parse the CISBenchmarkReport from the logs Reader
	report, err = s.converter.Convert(logsReader)
	if err != nil {
		err = fmt.Errorf("parsing CIS benchmark report: %w", err)
		return
	}

	return
}

func (s *Scanner) prepareKubeBenchJob(node core.Node) *batch.Job {
	target := "node"
	if _, ok := node.Labels[masterNodeLabel]; ok {
		target = "master"
	}
	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: kube.NamespaceStarboard,
			Labels: labels.Set{
				"app.kubernetes.io/name": "starboard-cli",
				kube.LabelResourceKind:   string(kube.KindNode),
				kube.LabelResourceName:   node.Name,
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Labels: labels.Set{
						"app.kubernetes.io/name": "starboard-cli",
						kube.LabelResourceKind:   string(kube.KindNode),
						kube.LabelResourceName:   node.Name,
					},
				},
				Spec: core.PodSpec{
					RestartPolicy: core.RestartPolicyNever,
					HostPID:       true,
					NodeName:      node.Name,
					Volumes: []core.Volume{
						{
							Name: "var-lib-etcd",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/var/lib/etcd",
								},
							},
						},
						{
							Name: "var-lib-kubelet",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/var/lib/kubelet",
								},
							},
						},
						{
							Name: "etc-systemd",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/etc/systemd",
								},
							},
						},
						{
							Name: "etc-kubernetes",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/etc/kubernetes",
								},
							},
						},
						{
							Name: "usr-bin",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/usr/bin",
								},
							},
						},
					},
					Containers: []core.Container{
						{
							Name:                     kubeBenchContainerName,
							Image:                    kubeBenchContainerImage,
							ImagePullPolicy:          core.PullIfNotPresent,
							TerminationMessagePolicy: core.TerminationMessageFallbackToLogsOnError,
							Command:                  []string{"kube-bench", target},
							Args:                     []string{"--json"},
							Resources: core.ResourceRequirements{
								Limits: core.ResourceList{
									core.ResourceCPU:    resource.MustParse("300m"),
									core.ResourceMemory: resource.MustParse("300M"),
								},
								Requests: core.ResourceList{
									core.ResourceCPU:    resource.MustParse("50m"),
									core.ResourceMemory: resource.MustParse("50M"),
								},
							},
							VolumeMounts: []core.VolumeMount{
								{
									Name:      "var-lib-etcd",
									MountPath: "/var/lib/etcd",
									ReadOnly:  true,
								},
								{
									Name:      "var-lib-kubelet",
									MountPath: "/var/lib/kubelet",
									ReadOnly:  true,
								},
								{
									Name:      "etc-systemd",
									MountPath: "/etc/systemd",
									ReadOnly:  true,
								},
								{
									Name:      "etc-kubernetes",
									MountPath: "/etc/kubernetes",
									ReadOnly:  true,
								},
								{
									Name:      "usr-bin",
									MountPath: "/usr/local/mount-from-host/bin",
									ReadOnly:  true,
								},
							},
						},
					},
				},
			},
		},
	}
}
