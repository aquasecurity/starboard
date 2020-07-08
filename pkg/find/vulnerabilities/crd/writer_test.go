package crd

import (
	"context"
	"testing"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned/fake"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	vulnerabilityReport01 = v1alpha1.VulnerabilityReport{
		Vulnerabilities: []v1alpha1.VulnerabilityItem{
			{VulnerabilityID: "CVE-2020-1832"},
		},
	}
	vulnerabilityReport02 = v1alpha1.VulnerabilityReport{
		Vulnerabilities: []v1alpha1.VulnerabilityItem{
			{VulnerabilityID: "CVE-2019-8211"},
		},
	}
)

func TestReadWriter_Read(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1alpha1.Vulnerability{
		TypeMeta: meta.TypeMeta{
			Kind:       "Vulnerability",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: meta.ObjectMeta{
			Namespace: "my-namespace",
			Name:      "my-deploy-my-container-01",
			Labels: map[string]string{
				kube.LabelResourceKind:      string(kube.KindDeployment),
				kube.LabelResourceName:      "my-deploy",
				kube.LabelResourceNamespace: "my-namespace",
				kube.LabelContainerName:     "my-container-01",
			},
		},
		Report: vulnerabilityReport01,
	}, &v1alpha1.Vulnerability{
		TypeMeta: meta.TypeMeta{
			Kind:       "Vulnerability",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: meta.ObjectMeta{
			Namespace: "my-namespace",
			Name:      "my-deploy-my-container-02",
			Labels: map[string]string{
				kube.LabelResourceKind:      string(kube.KindDeployment),
				kube.LabelResourceName:      "my-deploy",
				kube.LabelResourceNamespace: "my-namespace",
				kube.LabelContainerName:     "my-container-02",
			},
		},
		Report: vulnerabilityReport02,
	}, &v1alpha1.Vulnerability{
		TypeMeta: meta.TypeMeta{
			Kind:       "Vulnerability",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: meta.ObjectMeta{
			Namespace: "my-namespace",
			Name:      "my-sts",
			Labels: map[string]string{
				kube.LabelResourceKind:      string(kube.KindStatefulSet),
				kube.LabelResourceName:      "my-sts",
				kube.LabelResourceNamespace: "my-namespace",
				kube.LabelContainerName:     "my-sts-container",
			},
		},
		Report: v1alpha1.VulnerabilityReport{},
	})

	reports, err := NewReadWriter(clientset).Read(context.TODO(), kube.Object{
		Kind:      kube.KindDeployment,
		Name:      "my-deploy",
		Namespace: "my-namespace",
	})
	require.NoError(t, err)

	assert.Equal(t, vulnerabilities.WorkloadVulnerabilities{
		"my-container-01": vulnerabilityReport01,
		"my-container-02": vulnerabilityReport02,
	}, reports)
}
