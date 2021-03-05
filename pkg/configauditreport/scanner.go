package configauditreport

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/starboard"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Scanner struct {
	scheme     *runtime.Scheme
	clientset  kubernetes.Interface
	opts       kube.ScannerOpts
	pods       *pod.Manager
	logsReader kube.LogsReader
	plugin     Plugin
	ext.IDGenerator
}

func NewScanner(
	scheme *runtime.Scheme,
	clientset kubernetes.Interface,
	opts kube.ScannerOpts,
	plugin Plugin,
) *Scanner {
	return &Scanner{
		scheme:      scheme,
		clientset:   clientset,
		opts:        opts,
		plugin:      plugin,
		pods:        pod.NewPodManager(clientset),
		logsReader:  kube.NewLogsReader(clientset),
		IDGenerator: ext.NewGoogleUUIDGenerator(),
	}
}

func (s *Scanner) Scan(ctx context.Context, workload kube.Object, gvk schema.GroupVersionKind) (v1alpha1.ConfigAuditReport, error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)

	_, owner, err := s.pods.GetPodSpecByWorkload(ctx, workload)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	klog.V(3).Infof("Scanning with options: %+v", s.opts)
	job, secrets, err := s.getScanJob(workload, owner, gvk)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	err = runner.New().Run(ctx, kube.NewRunnableJob(s.scheme, s.clientset, job, secrets...))
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("running scan job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		klog.V(3).Infof("Deleting scan job: %s/%s", job.Namespace, job.Name)
		background := metav1.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	containerName := s.plugin.GetContainerName()

	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", containerName,
		job.Namespace, job.Name)
	logsStream, err := s.logsReader.GetLogsByJobAndContainerName(ctx, job, containerName)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("getting logs: %w", err)
	}

	result, err := s.plugin.ParseConfigAuditResult(logsStream)
	defer func() {
		_ = logsStream.Close()
	}()

	return NewBuilder(s.scheme).
		Owner(owner).
		Result(result).
		Get()
}

func (s *Scanner) getScanJob(workload kube.Object, obj client.Object, gvk schema.GroupVersionKind) (*batchv1.Job, []*corev1.Secret, error) {
	jobSpec, secrets, err := s.plugin.GetScanJobSpec(workload, obj, gvk)
	if err != nil {
		return nil, nil, err
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.GenerateID(),
			Namespace: starboard.NamespaceName,
			Labels: map[string]string{
				kube.LabelResourceKind:      string(workload.Kind),
				kube.LabelResourceName:      workload.Name,
				kube.LabelResourceNamespace: workload.Namespace,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind:      string(workload.Kind),
						kube.LabelResourceName:      workload.Name,
						kube.LabelResourceNamespace: workload.Namespace,
					},
				},
				Spec: jobSpec,
			},
		},
	}, secrets, nil
}
