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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReadWriter(t *testing.T) {

	kubernetesScheme := starboard.NewScheme()

	t.Run("Should create ConfigAuditReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		readWriter := configauditreport.NewReadWriter(client)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					starboard.LabelResourceKind:      "Deployment",
					starboard.LabelResourceName:      "app",
					starboard.LabelResourceNamespace: "qa",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
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
					starboard.LabelResourceKind:      "Deployment",
					starboard.LabelResourceName:      "app",
					starboard.LabelResourceNamespace: "qa",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}, found)
	})

	t.Run("Should update ConfigAuditReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "deployment-app",
				Namespace:       "qa",
				ResourceVersion: "0",
				Labels: map[string]string{
					starboard.LabelResourceKind:      "Deployment",
					starboard.LabelResourceName:      "app",
					starboard.LabelResourceNamespace: "qa",
					starboard.LabelResourceSpecHash:  "h1",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}).Build()
		readWriter := configauditreport.NewReadWriter(client)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "deployment-app",
				Namespace: "qa",
				Labels: map[string]string{
					starboard.LabelResourceKind:      "Deployment",
					starboard.LabelResourceName:      "app",
					starboard.LabelResourceNamespace: "qa",
					starboard.LabelResourceSpecHash:  "h2",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      9,
					CriticalCount: 2,
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
					starboard.LabelResourceKind:      "Deployment",
					starboard.LabelResourceName:      "app",
					starboard.LabelResourceNamespace: "qa",
					starboard.LabelResourceSpecHash:  "h2",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should find ConfigAuditReport by owner", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.ConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "my-namespace",
					Name:            "deployment-my-deploy-my",
					ResourceVersion: "0",
					Labels: map[string]string{
						starboard.LabelResourceKind:      string(kube.KindDeployment),
						starboard.LabelResourceName:      "my-deploy",
						starboard.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{},
			}, &v1alpha1.ConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "my-namespace",
					Name:      "my-sts",
					Labels: map[string]string{
						starboard.LabelResourceKind:      string(kube.KindStatefulSet),
						starboard.LabelResourceName:      "my-sts",
						starboard.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{},
			}).Build()

		readWriter := configauditreport.NewReadWriter(client)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindDeployment,
			Name:      "my-deploy",
			Namespace: "my-namespace",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "my-namespace",
				Name:            "deployment-my-deploy-my",
				ResourceVersion: "0",
				Labels: map[string]string{
					starboard.LabelResourceKind:      string(kube.KindDeployment),
					starboard.LabelResourceName:      "my-deploy",
					starboard.LabelResourceNamespace: "my-namespace",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}, found)
	})

	t.Run("Should find ConfigAuditReport by owner with special name", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.ConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "kube-system",
					Name:            "role-79f88497",
					ResourceVersion: "0",
					Labels: map[string]string{
						starboard.LabelResourceKind:      "Role",
						starboard.LabelResourceNameHash:  "79f88497",
						starboard.LabelResourceNamespace: "kube-system",
					},
					Annotations: map[string]string{
						starboard.LabelResourceName: "system:controller:cloud-provider",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{},
			}, &v1alpha1.ConfigAuditReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "kube-system",
					Name:            "role-868458b9d6",
					ResourceVersion: "0",
					Labels: map[string]string{
						starboard.LabelResourceKind:      "Role",
						starboard.LabelResourceNameHash:  "868458b9d6",
						starboard.LabelResourceNamespace: "kube-system",
					},
					Annotations: map[string]string{
						starboard.LabelResourceName: "system:controller:token-cleaner",
					},
				},
				Report: v1alpha1.ConfigAuditReportData{},
			}).Build()

		readWriter := configauditreport.NewReadWriter(client)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindRole,
			Name:      "system:controller:token-cleaner",
			Namespace: "kube-system",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "kube-system",
				Name:            "role-868458b9d6",
				ResourceVersion: "0",
				Labels: map[string]string{
					starboard.LabelResourceKind:      "Role",
					starboard.LabelResourceNameHash:  "868458b9d6",
					starboard.LabelResourceNamespace: "kube-system",
				},
				Annotations: map[string]string{
					starboard.LabelResourceName: "system:controller:token-cleaner",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}, found)
	})

	t.Run("Should create ClusterConfigAuditReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		readWriter := configauditreport.NewReadWriter(client)
		err := readWriter.WriteClusterReport(context.TODO(), v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					starboard.LabelResourceKind: "ClusterRole",
					starboard.LabelResourceName: "admin",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ClusterConfigAuditReport
		err = client.Get(context.TODO(), types.NamespacedName{Name: "clusterrole-admin"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ClusterConfigAuditReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterConfigAuditReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					starboard.LabelResourceKind: "ClusterRole",
					starboard.LabelResourceName: "admin",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}, found)
	})

	t.Run("Should update ClusterConfigAuditReport", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(kubernetesScheme).
			WithObjects(
				&v1alpha1.ClusterConfigAuditReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "clusterrole-admin",
						ResourceVersion: "0",
						Labels: map[string]string{
							starboard.LabelResourceKind:     "ClusterRole",
							starboard.LabelResourceName:     "admin",
							starboard.LabelResourceSpecHash: "h1",
						},
					},
					Report: v1alpha1.ConfigAuditReportData{
						Summary: v1alpha1.ConfigAuditSummary{
							LowCount:      8,
							CriticalCount: 3,
						},
					},
				}).
			Build()
		readWriter := configauditreport.NewReadWriter(client)
		err := readWriter.WriteClusterReport(context.TODO(), v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					starboard.LabelResourceKind:     "ClusterRole",
					starboard.LabelResourceName:     "admin",
					starboard.LabelResourceSpecHash: "h2",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.ClusterConfigAuditReport
		err = client.Get(context.TODO(), types.NamespacedName{Name: "clusterrole-admin"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.ClusterConfigAuditReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterConfigAuditReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-admin",
				Labels: map[string]string{
					starboard.LabelResourceKind:     "ClusterRole",
					starboard.LabelResourceName:     "admin",
					starboard.LabelResourceSpecHash: "h2",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should find ClusterConfigAuditReport by owner", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(kubernetesScheme).
			WithObjects(
				&v1alpha1.ClusterConfigAuditReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "clusterrole-viewer",
						ResourceVersion: "1",
						Labels: map[string]string{
							starboard.LabelResourceKind:      "ClusterRole",
							starboard.LabelResourceName:      "viewer",
							starboard.LabelResourceNamespace: "",
						},
					},
					Report: v1alpha1.ConfigAuditReportData{},
				},
				&v1alpha1.ClusterConfigAuditReport{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "clusterrole-editor",
						ResourceVersion: "1",
						Labels: map[string]string{
							starboard.LabelResourceKind:      "ClusterRole",
							starboard.LabelResourceName:      "editor",
							starboard.LabelResourceNamespace: "",
						},
					},
					Report: v1alpha1.ConfigAuditReportData{},
				}).
			Build()

		readWriter := configauditreport.NewReadWriter(client)
		found, err := readWriter.FindClusterReportByOwner(context.TODO(), kube.ObjectRef{
			Kind: "ClusterRole",
			Name: "editor",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "clusterrole-editor",
				ResourceVersion: "1",
				Labels: map[string]string{
					starboard.LabelResourceKind:      "ClusterRole",
					starboard.LabelResourceName:      "editor",
					starboard.LabelResourceNamespace: "",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}, found)
	})
}
