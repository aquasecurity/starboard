package configauditreport_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeKubernetes "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReadWriter(t *testing.T) {

	kubernetesScheme := starboard.NewScheme()

	t.Run("Should create ConfigAuditReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		readWriter := configauditreport.NewReadWriter(client, fakeKubernetes.NewSimpleClientset())
		err := readWriter.Write(context.TODO(), v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					"starboard.resource.kind":      "Deployment",
					"starboard.resource.name":      "app",
					"starboard.resource.namespace": "qa",
				},
			},
			Report: v1alpha1.ConfigAuditResult{
				Summary: v1alpha1.ConfigAuditSummary{
					WarningCount: 8,
					DangerCount:  3,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ConfigAuditReport
		err = client.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "deployment-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ConfigAuditReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigAuditReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					"starboard.resource.kind":      "Deployment",
					"starboard.resource.name":      "app",
					"starboard.resource.namespace": "qa",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditResult{
				Summary: v1alpha1.ConfigAuditSummary{
					WarningCount: 8,
					DangerCount:  3,
				},
			},
		}, found)
	})

	t.Run("Should update ConfigAuditReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					"starboard.resource.kind":      "Deployment",
					"starboard.resource.name":      "app",
					"starboard.resource.namespace": "qa",
					"pod-spec-hash":                "h1",
				},
			},
			Report: v1alpha1.ConfigAuditResult{
				Summary: v1alpha1.ConfigAuditSummary{
					WarningCount: 8,
					DangerCount:  3,
				},
			},
		}).Build()
		readWriter := configauditreport.NewReadWriter(client, fakeKubernetes.NewSimpleClientset())
		err := readWriter.Write(context.TODO(), v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					"starboard.resource.kind":      "Deployment",
					"starboard.resource.name":      "app",
					"starboard.resource.namespace": "qa",
					"pod-spec-hash":                "h2",
				},
			},
			Report: v1alpha1.ConfigAuditResult{
				Summary: v1alpha1.ConfigAuditSummary{
					WarningCount: 9,
					DangerCount:  2,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ConfigAuditReport
		err = client.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "deployment-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ConfigAuditReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigAuditReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					"starboard.resource.kind":      "Deployment",
					"starboard.resource.name":      "app",
					"starboard.resource.namespace": "qa",
					"pod-spec-hash":                "h2",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditResult{
				Summary: v1alpha1.ConfigAuditSummary{
					WarningCount: 9,
					DangerCount:  2,
				},
			},
		}, found)
	})

	t.Run("Should find ConfigAuditReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "my-namespace",
				Name:      "deployment-my-deploy-my",
				Labels: map[string]string{
					kube.LabelResourceKind:      string(kube.KindDeployment),
					kube.LabelResourceName:      "my-deploy",
					kube.LabelResourceNamespace: "my-namespace",
				},
			},
			Report: v1alpha1.ConfigAuditResult{},
		}, &v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "my-namespace",
				Name:      "my-sts",
				Labels: map[string]string{
					kube.LabelResourceKind:      string(kube.KindStatefulSet),
					kube.LabelResourceName:      "my-sts",
					kube.LabelResourceNamespace: "my-namespace",
				},
			},
			Report: v1alpha1.ConfigAuditResult{},
		}).Build()

		readWriter := configauditreport.NewReadWriter(client, fakeKubernetes.NewSimpleClientset())
		found, err := readWriter.FindByOwner(context.TODO(), kube.Object{
			Kind:      kube.KindDeployment,
			Name:      "my-deploy",
			Namespace: "my-namespace",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "my-namespace",
				Name:      "deployment-my-deploy-my",
				Labels: map[string]string{
					kube.LabelResourceKind:      string(kube.KindDeployment),
					kube.LabelResourceName:      "my-deploy",
					kube.LabelResourceNamespace: "my-namespace",
				},
			},
			Report: v1alpha1.ConfigAuditResult{},
		}, found)
	})
}
