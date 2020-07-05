package crd

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/kube"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	clientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/google/uuid"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type writer struct {
	client clientset.Interface
}

func NewWriter(client clientset.Interface) vulnerabilities.Writer {
	return &writer{
		client: client,
	}
}

func (s *writer) Write(ctx context.Context, workload kube.Object, reports map[string]starboard.VulnerabilityReport) (err error) {
	for container, report := range reports {
		if workload.Kind == kube.KindImage {
			if err = s.createContainerVulnerability(ctx, workload, report); err != nil {
				return
			}
			continue
		}
		err = s.createVulnerability(ctx, workload, container, report)
		if err != nil {
			return
		}
	}
	return
}

func (s *writer) createVulnerability(ctx context.Context, workload kube.Object, container string, report starboard.VulnerabilityReport) (err error) {
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

func (s *writer) createContainerVulnerability(ctx context.Context, workload kube.Object, report starboard.VulnerabilityReport) (err error) {
	_, err = s.client.AquasecurityV1alpha1().ContainerVulnerabilities().Create(ctx, &starboard.ContainerVulnerability{
		ObjectMeta: meta.ObjectMeta{
			Name: fmt.Sprintf(uuid.New().String()),
			Labels: map[string]string{
				kube.LabelResourceKind: string(workload.Kind),
			},
		},
		Report: report,
	}, meta.CreateOptions{})

	return err
}
