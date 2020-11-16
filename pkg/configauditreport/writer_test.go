package configauditreport_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned/fake"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestReadWriter(t *testing.T) {

	t.Run("Should create ConfigAuditReport", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()
		err := configauditreport.NewReadWriter(clientset).Write(context.TODO(), v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-nginx",
				Namespace: "qa",
				Labels: map[string]string{
					kube.LabelResourceKind:      "Deployment",
					kube.LabelResourceName:      "nginx",
					kube.LabelResourceNamespace: "qa",
					kube.LabelPodSpecHash:       "abc",
				},
			},
			Report: v1alpha1.ConfigAuditResult{},
		})
		require.NoError(t, err)

		_, err = clientset.AquasecurityV1alpha1().ConfigAuditReports("qa").
			Get(context.TODO(), "deployment-nginx", metav1.GetOptions{})
		require.NoError(t, err)
	})

	t.Run("Should update ConfigAuditReport", func(t *testing.T) {
		clientset := fake.NewSimpleClientset(&v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-wordpress",
				Namespace: "prod",
				Labels: map[string]string{
					kube.LabelResourceKind:      "Deployment",
					kube.LabelResourceName:      "wordpress",
					kube.LabelResourceNamespace: "prod",
					kube.LabelPodSpecHash:       "abc",
				},
			},
			Report: v1alpha1.ConfigAuditResult{},
		})
		err := configauditreport.NewReadWriter(clientset).Write(context.TODO(), v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-wordpress",
				Namespace: "prod",
				Labels: map[string]string{
					kube.LabelResourceKind:      "Deployment",
					kube.LabelResourceName:      "wordpress",
					kube.LabelResourceNamespace: "prod",
					kube.LabelPodSpecHash:       "xyz",
				},
			},
			Report: v1alpha1.ConfigAuditResult{},
		})
		require.NoError(t, err)
		report, err := clientset.AquasecurityV1alpha1().ConfigAuditReports("prod").
			Get(context.TODO(), "deployment-wordpress", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			kube.LabelResourceKind:      "Deployment",
			kube.LabelResourceName:      "wordpress",
			kube.LabelResourceNamespace: "prod",
			kube.LabelPodSpecHash:       "xyz",
		}, report.Labels)
	})

	t.Run("Should find ConfigAuditReport", func(t *testing.T) {
		clientset := fake.NewSimpleClientset(&v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-wordpress",
				Namespace: "prod",
				Labels: map[string]string{
					kube.LabelResourceKind:      "Deployment",
					kube.LabelResourceName:      "wordpress",
					kube.LabelResourceNamespace: "prod",
					kube.LabelPodSpecHash:       "abc",
				},
			},
			Report: v1alpha1.ConfigAuditResult{},
		}, &v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-wordpress",
				Namespace: "qa",
				Labels: map[string]string{
					kube.LabelResourceKind:      "Deployment",
					kube.LabelResourceName:      "wordpress",
					kube.LabelResourceNamespace: "qa",
					kube.LabelPodSpecHash:       "abc",
				},
			},
			Report: v1alpha1.ConfigAuditResult{},
		})

		report, err := configauditreport.NewReadWriter(clientset).FindByOwner(context.TODO(), kube.Object{
			Kind:      kube.KindDeployment,
			Name:      "wordpress",
			Namespace: "qa",
		})
		require.NoError(t, err)
		assert.Equal(t, "deployment-wordpress", report.Name)
		assert.Equal(t, map[string]string{
			kube.LabelResourceKind:      "Deployment",
			kube.LabelResourceName:      "wordpress",
			kube.LabelResourceNamespace: "qa",
			kube.LabelPodSpecHash:       "abc",
		}, report.Labels)
	})

}
