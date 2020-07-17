package crd

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/kube"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	clientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ReadWriter struct {
	scheme *runtime.Scheme
	client clientset.Interface
}

func NewReadWriter(scheme *runtime.Scheme, client clientset.Interface) *ReadWriter {
	return &ReadWriter{
		scheme: scheme,
		client: client,
	}
}

func (s *ReadWriter) Write(ctx context.Context, reports vulnerabilities.WorkloadVulnerabilities, owner metav1.Object) (err error) {
	for container, report := range reports {
		err = s.createVulnerability(ctx, container, report, owner)
		if err != nil {
			return
		}
	}
	return
}

func (s *ReadWriter) createVulnerability(ctx context.Context, container string, report starboard.VulnerabilityScanResult, owner metav1.Object) (err error) {
	namespace := owner.GetNamespace()
	name := owner.GetName()
	kind, err := kube.KindForObject(owner, s.scheme)
	if err != nil {
		return err
	}

	// Trying to find previously generated vulnerability report for this specific container
	vulnsSearch, err := s.client.AquasecurityV1alpha1().VulnerabilityReports(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{
			kube.LabelResourceKind:  kind,
			kube.LabelResourceName:  name,
			kube.LabelContainerName: container,
		}.String(),
	})
	if err != nil {
		return
	}

	if len(vulnsSearch.Items) > 0 {
		existingCR := vulnsSearch.Items[0]
		klog.V(3).Infof("Updating vulnerability report: %s/%s", namespace, name)
		deepCopy := existingCR.DeepCopy()
		deepCopy.Report = report
		_, err = s.client.AquasecurityV1alpha1().VulnerabilityReports(namespace).Update(ctx, deepCopy, metav1.UpdateOptions{})
	} else {
		klog.V(3).Infof("Creating vulnerability report: %s/%s", namespace, name)
		report := &starboard.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf(uuid.New().String()),
				Namespace: namespace,
				Labels: map[string]string{
					kube.LabelResourceKind:      kind,
					kube.LabelResourceName:      name,
					kube.LabelResourceNamespace: namespace,
					kube.LabelContainerName:     container,
				},
			},
			Report: report,
		}
		err = kube.SetOwnerReference(owner, report, s.scheme)
		if err != nil {
			return err
		}
		_, err = s.client.AquasecurityV1alpha1().VulnerabilityReports(namespace).
			Create(ctx, report, metav1.CreateOptions{})
	}

	return err
}

func (s *ReadWriter) Read(ctx context.Context, workload kube.Object) (vulnerabilities.WorkloadVulnerabilities, error) {
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
