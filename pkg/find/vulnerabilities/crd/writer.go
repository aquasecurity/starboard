package crd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	clientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type readWriter struct {
	scheme *runtime.Scheme
	client clientset.Interface
}

func NewReadWriter(scheme *runtime.Scheme, client clientset.Interface) vulnerabilities.ReadWriter {
	return &readWriter{
		scheme: scheme,
		client: client,
	}
}

func (s *readWriter) Write(ctx context.Context, reports vulnerabilities.WorkloadVulnerabilities, owner metav1.Object) error {
	for container, report := range reports {
		err := s.createOrUpdate(ctx, container, report, owner)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *readWriter) createOrUpdate(ctx context.Context, container string, scanResult starboard.VulnerabilityScanResult, owner metav1.Object) error {
	namespace := owner.GetNamespace()

	reportName, err := vulnerabilityreport.NewNameBuilder(s.scheme).
		Owner(owner).
		Container(container).Get()

	if err != nil {
		return err
	}

	report, err := s.client.AquasecurityV1alpha1().VulnerabilityReports(owner.GetNamespace()).
		Get(ctx, reportName, metav1.GetOptions{})

	if err == nil && report != nil {
		klog.V(3).Infof("Updating VulnerabilityReport %q", namespace+"/"+reportName)
		deepCopy := report.DeepCopy()
		deepCopy.Report = scanResult
		_, err = s.client.AquasecurityV1alpha1().VulnerabilityReports(namespace).
			Update(ctx, deepCopy, metav1.UpdateOptions{})
		return err
	}

	if errors.IsNotFound(err) {
		klog.V(3).Infof("Creating VulnerabilityReport %q", namespace+"/"+reportName)
		report, err := vulnerabilityreport.NewBuilder(s.scheme).
			Owner(owner).
			Container(container).
			ScanResult(scanResult).
			ReportName(reportName).
			Get()
		if err != nil {
			return err
		}
		_, err = s.client.AquasecurityV1alpha1().VulnerabilityReports(namespace).
			Create(ctx, &report, metav1.CreateOptions{})
		return err
	}

	return err
}

func (s *readWriter) Read(ctx context.Context, workload kube.Object) (vulnerabilities.WorkloadVulnerabilities, error) {
	list, err := s.client.AquasecurityV1alpha1().VulnerabilityReports(workload.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{
			kube.LabelResourceKind:      string(workload.Kind),
			kube.LabelResourceName:      workload.Name,
			kube.LabelResourceNamespace: workload.Namespace,
		}.String(),
	})
	if err != nil {
		return vulnerabilities.WorkloadVulnerabilities{}, err
	}
	reports := make(map[string]starboard.VulnerabilityScanResult)
	for _, item := range list.Items {
		if container, ok := item.Labels[kube.LabelContainerName]; ok {
			reports[container] = item.Report
		}
	}
	return reports, nil
}
