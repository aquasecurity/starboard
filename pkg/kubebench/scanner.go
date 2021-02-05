package kubebench

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"k8s.io/utils/pointer"
)

const (
	kubeBenchContainerName = "kube-bench"
)

type Config interface {
	GetKubeBenchImageRef() (string, error)
}

type Scanner struct {
	scheme     *runtime.Scheme
	config     Config
	opts       kube.ScannerOpts
	clientset  kubernetes.Interface
	pods       *pod.Manager
	logsReader kube.LogsReader
	converter  *Converter
}

func NewScanner(
	scheme *runtime.Scheme,
	clientset kubernetes.Interface,
	config Config,
	opts kube.ScannerOpts,
) *Scanner {
	return &Scanner{
		scheme:     scheme,
		config:     config,
		opts:       opts,
		clientset:  clientset,
		pods:       pod.NewPodManager(clientset),
		logsReader: kube.NewLogsReader(clientset),
		converter: &Converter{
			Clock:  ext.NewSystemClock(),
			Config: config,
		},
	}
}

func (s *Scanner) Scan(ctx context.Context, node corev1.Node) (v1alpha1.CISKubeBenchOutput, error) {
	// 1. Prepare descriptor for the Kubernetes Job which will run kube-bench
	job, err := s.prepareKubeBenchJob(node)
	if err != nil {
		return v1alpha1.CISKubeBenchOutput{}, err
	}

	// 2. Run the prepared Job and wait for its completion or failure
	err = runner.New().Run(ctx, kube.NewRunnableJob(s.scheme, s.clientset, job))
	if err != nil {
		return v1alpha1.CISKubeBenchOutput{}, fmt.Errorf("running kube-bench job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		// 5. Delete the kube-bench Job
		klog.V(3).Infof("Deleting job: %s/%s", job.Namespace, job.Name)
		background := metav1.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	// 3. Get kube-bench JSON output from the kube-bench Pod
	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", kubeBenchContainerName,
		job.Namespace, job.Name)
	logsStream, err := s.logsReader.GetLogsByJobAndContainerName(ctx, job, kubeBenchContainerName)
	if err != nil {
		return v1alpha1.CISKubeBenchOutput{}, fmt.Errorf("getting logs: %w", err)
	}
	defer func() {
		_ = logsStream.Close()
	}()

	// 4. Parse the CISBenchmarkReport from the logs Reader
	return s.converter.Convert(logsStream)
}

func (s *Scanner) prepareKubeBenchJob(node corev1.Node) (*batchv1.Job, error) {
	imageRef, err := s.config.GetKubeBenchImageRef()
	if err != nil {
		return nil, err
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: starboard.NamespaceName,
			Labels: labels.Set{
				"app.kubernetes.io/name": "starboard-cli",
				kube.LabelResourceKind:   string(kube.KindNode),
				kube.LabelResourceName:   node.Name,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels.Set{
						"app.kubernetes.io/name": "starboard-cli",
						kube.LabelResourceKind:   string(kube.KindNode),
						kube.LabelResourceName:   node.Name,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:           starboard.ServiceAccountName,
					AutomountServiceAccountToken: pointer.BoolPtr(true),
					RestartPolicy:                corev1.RestartPolicyNever,
					HostPID:                      true,
					NodeName:                     node.Name,
					Volumes: []corev1.Volume{
						{
							Name: "var-lib-etcd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/etcd",
								},
							},
						},
						{
							Name: "var-lib-kubelet",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/kubelet",
								},
							},
						},
						{
							Name: "etc-systemd",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/systemd",
								},
							},
						},
						{
							Name: "etc-kubernetes",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/kubernetes",
								},
							},
						},
						{
							Name: "usr-bin",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/usr/bin",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:                     kubeBenchContainerName,
							Image:                    imageRef,
							ImagePullPolicy:          corev1.PullIfNotPresent,
							TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
							Command:                  []string{"sh"},
							Args:                     []string{"-c", "kube-bench --json 2> /dev/null"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("300m"),
									corev1.ResourceMemory: resource.MustParse("300M"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("50M"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
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
	}, nil
}
