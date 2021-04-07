package configauditreport

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/starboard"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Scanner struct {
	scheme         *runtime.Scheme
	clientset      kubernetes.Interface
	opts           kube.ScannerOpts
	objectResolver *kube.ObjectResolver
	logsReader     kube.LogsReader
	plugin         Plugin
	pluginContext  starboard.PluginContext
	ext.IDGenerator
}

func NewScanner(
	clientset kubernetes.Interface,
	client client.Client,
	opts kube.ScannerOpts,
	plugin Plugin,
	pluginContext starboard.PluginContext,
) *Scanner {
	return &Scanner{
		scheme:         client.Scheme(),
		clientset:      clientset,
		opts:           opts,
		plugin:         plugin,
		pluginContext:  pluginContext,
		objectResolver: &kube.ObjectResolver{Client: client},
		logsReader:     kube.NewLogsReader(clientset),
		IDGenerator:    ext.NewGoogleUUIDGenerator(),
	}
}

func (s *Scanner) Scan(ctx context.Context, workload kube.Object) (v1alpha1.ConfigAuditReport, error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)

	owner, err := s.objectResolver.GetObjectFromPartialObject(ctx, workload)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	klog.V(3).Infof("Scanning with options: %+v", s.opts)
	job, secrets, err := s.getScanJob(owner)
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

	result, err := s.plugin.ParseConfigAuditReportData(logsStream)
	defer func() {
		_ = logsStream.Close()
	}()

	return NewBuilder(s.scheme).
		Controller(owner).
		Result(result).
		Get()
}

func (s *Scanner) getScanJob(obj client.Object) (*batchv1.Job, []*corev1.Secret, error) {
	jobSpec, secrets, err := s.plugin.GetScanJobSpec(s.pluginContext, obj)
	if err != nil {
		return nil, nil, err
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.GenerateID(),
			Namespace: starboard.NamespaceName,
			Labels: map[string]string{
				starboard.LabelResourceKind:      obj.GetObjectKind().GroupVersionKind().Kind,
				starboard.LabelResourceName:      obj.GetName(),
				starboard.LabelResourceNamespace: obj.GetNamespace(),
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						starboard.LabelResourceKind:      obj.GetObjectKind().GroupVersionKind().Kind,
						starboard.LabelResourceName:      obj.GetName(),
						starboard.LabelResourceNamespace: obj.GetNamespace(),
					},
				},
				Spec: jobSpec,
			},
		},
	}, secrets, nil
}
