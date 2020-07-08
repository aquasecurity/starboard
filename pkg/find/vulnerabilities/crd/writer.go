package crd

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/aquasecurity/starboard/pkg/kube"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	clientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/google/uuid"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ReadWriter struct {
	client clientset.Interface
}

func NewReadWriter(client clientset.Interface) *ReadWriter {
	return &ReadWriter{
		client: client,
	}
}

func (s *ReadWriter) Write(ctx context.Context, workload kube.Object, reports vulnerabilities.WorkloadVulnerabilities) (err error) {
	for container, report := range reports {
		err = s.createVulnerability(ctx, workload, container, report)
		if err != nil {
			return
		}
	}
	return
}

func (s *ReadWriter) createVulnerability(ctx context.Context, workload kube.Object, container string, report starboard.VulnerabilityReport) (err error) {
	_, err = s.client.AquasecurityV1alpha1().Vulnerabilities(workload.Namespace).Create(ctx, &starboard.Vulnerability{
		ObjectMeta: meta.ObjectMeta{
			Name: fmt.Sprintf(uuid.New().String()),
			Labels: map[string]string{
				kube.LabelResourceKind:      string(workload.Kind),
				kube.LabelResourceName:      workload.Name,
				kube.LabelResourceNamespace: workload.Namespace,
				kube.LabelContainerName:     container,
			},
		},
		Report: report,
	}, meta.CreateOptions{})

	return err
}

func (s *ReadWriter) Read(ctx context.Context, workload kube.Object) (vulnerabilities.WorkloadVulnerabilities, error) {
	list, err := s.client.AquasecurityV1alpha1().Vulnerabilities(workload.Namespace).List(ctx, meta.ListOptions{
		LabelSelector: labels.Set{
			kube.LabelResourceKind:      string(workload.Kind),
			kube.LabelResourceName:      workload.Name,
			kube.LabelResourceNamespace: workload.Namespace,
		}.String(),
	})
	if err != nil {
		return vulnerabilities.WorkloadVulnerabilities{}, err
	}
	reports := make(map[string]starboard.VulnerabilityReport)
	for _, item := range list.Items {
		if container, ok := item.Labels[kube.LabelContainerName]; ok {
			reports[container] = item.Report
		}
	}
	return reports, nil
}
