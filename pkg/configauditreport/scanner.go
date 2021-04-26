package configauditreport

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/starboard"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
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
	}
}

func (s *Scanner) Scan(ctx context.Context, workload kube.Object) (v1alpha1.ConfigAuditReport, error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)

	owner, err := s.objectResolver.GetObjectFromPartialObject(ctx, workload)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	klog.V(3).Infof("Scanning with options: %+v", s.opts)
	job, secrets, err := NewScanJob().
		WithPlugin(s.plugin).
		WithPluginContext(s.pluginContext).
		WithTimeout(s.opts.ScanJobTimeout).
		WithObject(owner).
		Get()
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

	podSpecHash, ok := job.Labels[starboard.LabelPodSpecHash]
	if !ok {
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("expected label %s not set", starboard.LabelPodSpecHash)
	}
	pluginConfigHash, ok := job.Labels[starboard.LabelPluginConfigHash]
	if !ok {
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("expected label %s not set", starboard.LabelPluginConfigHash)
	}

	return NewReportBuilder(s.scheme).
		Controller(owner).
		PodSpecHash(podSpecHash).
		PluginConfigHash(pluginConfigHash).
		Data(result).
		Get()
}
