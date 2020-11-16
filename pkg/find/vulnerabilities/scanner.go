package vulnerabilities

import (
	"context"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/resources"

	"github.com/aquasecurity/starboard/pkg/ext"

	"github.com/aquasecurity/starboard/pkg/trivy"

	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/aquasecurity/starboard/pkg/scanners"
	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"
)

// NewScanner constructs a new vulnerability Scanner with the specified options and Kubernetes client Interface.
func NewScanner(scheme *runtime.Scheme, config starboard.TrivyConfig, opts kube.ScannerOpts, clientset kubernetes.Interface) *Scanner {
	idGenerator := ext.NewGoogleUUIDGenerator()
	return &Scanner{
		scheme:      scheme,
		config:      config,
		opts:        opts,
		clientset:   clientset,
		pods:        pod.NewPodManager(clientset),
		converter:   trivy.DefaultConverter,
		idGenerator: idGenerator,
		delegate:    trivy.NewScanner(idGenerator, config),
	}
}

type Scanner struct {
	scheme      *runtime.Scheme
	config      starboard.TrivyConfig
	opts        kube.ScannerOpts
	clientset   kubernetes.Interface
	pods        *pod.Manager
	converter   trivy.Converter
	idGenerator ext.IDGenerator
	delegate    vulnerabilityreport.Scanner
}

func (s *Scanner) Scan(ctx context.Context, workload kube.Object) ([]sec.VulnerabilityReport, error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)
	podSpec, owner, err := s.pods.GetPodSpecByWorkload(ctx, workload)
	if err != nil {
		return nil, fmt.Errorf("getting Pod template: %w", err)
	}

	reports, err := s.ScanByPodSpec(ctx, workload, podSpec, owner)
	if err != nil {
		return nil, err
	}
	return reports, nil
}

func (s *Scanner) ScanByPodSpec(ctx context.Context, workload kube.Object, spec corev1.PodSpec, owner metav1.Object) ([]sec.VulnerabilityReport, error) {
	klog.V(3).Infof("Scanning with options: %+v", s.opts)

	job, err := s.PrepareScanJob(workload, spec)
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
		background := metav1.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	klog.V(3).Infof("Scan job completed: %s/%s", job.Namespace, job.Name)

	job, err = s.clientset.BatchV1().Jobs(job.Namespace).Get(ctx, job.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting scan job: %w", err)
	}

	return s.GetVulnerabilityReportsByScanJob(ctx, job, owner)
}

func (s *Scanner) PrepareScanJob(workload kube.Object, spec corev1.PodSpec) (*batchv1.Job, error) {
	templateSpec, err := s.delegate.GetPodSpec(spec)
	if err != nil {
		return nil, err
	}

	templateSpec.ServiceAccountName = starboard.ServiceAccountName

	containerImagesAsJSON, err := resources.GetContainerImagesFromPodSpec(spec).AsJSON()
	if err != nil {
		return nil, err
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.idGenerator.GenerateID(),
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
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						kube.LabelResourceKind:      string(workload.Kind),
						kube.LabelResourceName:      workload.Name,
						kube.LabelResourceNamespace: workload.Namespace,
					},
				},
				Spec: templateSpec,
			},
		},
	}, nil
}

func (s *Scanner) GetVulnerabilityReportsByScanJob(ctx context.Context, job *batchv1.Job, owner metav1.Object) ([]sec.VulnerabilityReport, error) {
	var reports []sec.VulnerabilityReport

	var containerImagesAsJSON string
	var ok bool

	if containerImagesAsJSON, ok = job.Annotations[kube.AnnotationContainerImages]; !ok {
		return nil, fmt.Errorf("scan job does not have required annotation: %s", kube.AnnotationContainerImages)
	}
	containerImages := kube.ContainerImages{}
	err := containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		return nil, fmt.Errorf("reading scan job annotation: %s: %w", kube.AnnotationContainerImages, err)
	}

	for _, c := range job.Spec.Template.Spec.Containers {
		klog.V(3).Infof("Getting logs for %s container in job: %s/%s", c.Name, job.Namespace, job.Name)
		var logReader io.ReadCloser
		logReader, err = s.pods.GetContainerLogsByJob(ctx, job, c.Name)
		if err != nil {
			return nil, err
		}
		result, err := s.converter.Convert(s.config, containerImages[c.Name], logReader)

		report, err := vulnerabilityreport.NewBuilder(s.scheme).
			Owner(owner).
			Container(c.Name).
			Result(result).
			PodSpecHash("").Get()
		if err != nil {
			return nil, err
		}

		reports = append(reports, report)

		_ = logReader.Close()
	}
	return reports, nil
}
