package configauditreport

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/starboard"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
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
	config         starboard.ConfigData
}

func NewScanner(
	clientset kubernetes.Interface,
	client client.Client,
	plugin Plugin,
	pluginContext starboard.PluginContext,
	config starboard.ConfigData,
	opts kube.ScannerOpts,
) *Scanner {
	return &Scanner{
		scheme:         client.Scheme(),
		clientset:      clientset,
		opts:           opts,
		plugin:         plugin,
		pluginContext:  pluginContext,
		objectResolver: &kube.ObjectResolver{Client: client},
		logsReader:     kube.NewLogsReader(clientset),
		config:         config,
	}
}

func (s *Scanner) Scan(ctx context.Context, obj kube.Object) (*ReportBuilder, error) {
	if !s.plugin.SupportsKind(obj.Kind) {
		return nil, fmt.Errorf("kind %s is not supported by %s plugin", obj.Kind, s.pluginContext.GetName())
	}
	owner, err := s.objectResolver.GetObjectFromPartialObject(ctx, obj)
	if err != nil {
		return nil, err
	}

	scanJobTolerations, err := s.config.GetScanJobTolerations()
	if err != nil {
		return nil, fmt.Errorf("getting scan job tolerations: %w", err)
	}

	scanJobAnnotations, err := s.config.GetScanJobAnnotations()
	if err != nil {
		return nil, fmt.Errorf("getting scan job annotations: %w", err)
	}

	klog.V(3).Infof("Scanning with options: %+v", s.opts)
	job, secrets, err := NewScanJob().
		WithPlugin(s.plugin).
		WithPluginContext(s.pluginContext).
		WithTimeout(s.opts.ScanJobTimeout).
		WithObject(owner).
		WithTolerations(scanJobTolerations).
		WithAnnotations(scanJobAnnotations).
		Get()
	if err != nil {
		return nil, fmt.Errorf("constructing scan job: %w", err)
	}

	err = runner.New().Run(ctx, kube.NewRunnableJob(s.scheme, s.clientset, job, secrets...))
	if err != nil {
		return nil, fmt.Errorf("running scan job: %w", err)
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

	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", containerName, job.Namespace, job.Name)
	logsStream, err := s.logsReader.GetLogsByJobAndContainerName(ctx, job, containerName)
	if err != nil {
		return nil, fmt.Errorf("getting logs: %w", err)
	}

	result, err := s.plugin.ParseConfigAuditReportData(s.pluginContext, logsStream)
	defer func() {
		_ = logsStream.Close()
	}()

	resourceSpecHash, ok := job.Labels[starboard.LabelResourceSpecHash]
	if !ok {
		return nil, fmt.Errorf("expected label %s not set", starboard.LabelResourceSpecHash)
	}
	pluginConfigHash, ok := job.Labels[starboard.LabelPluginConfigHash]
	if !ok {
		return nil, fmt.Errorf("expected label %s not set", starboard.LabelPluginConfigHash)
	}

	return NewReportBuilder(s.scheme).
		Controller(owner).
		ResourceSpecHash(resourceSpecHash).
		PluginConfigHash(pluginConfigHash).
		Data(result), nil
}
