package crd

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/kube"

	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
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

func (s *writer) Write(workload kube.Workload, reports map[string]sec.VulnerabilityReport) (err error) {
	for container, report := range reports {
		err = s.createVulnerability(workload, container, report)
		if err != nil {
			return
		}
	}
	return
}

func (s *writer) createVulnerability(workload kube.Workload, container string, report sec.VulnerabilityReport) (err error) {
	_, err = s.client.AquasecurityV1alpha1().Vulnerabilities(workload.Namespace).Create(&sec.Vulnerability{
		ObjectMeta: meta.ObjectMeta{
			Name: fmt.Sprintf(uuid.New().String()),
			Labels: map[string]string{
				kube.LabelResourceKind:  workload.Kind.String(),
				kube.LabelResourceName:  workload.Name,
				kube.LabelContainerName: container,
			},
		},
		Report: report,
	})

	return err
}
