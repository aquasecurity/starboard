package configauditreport_test

import (
	"encoding/json"
	"fmt"
	. "github.com/onsi/gomega"

	"io"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestReportBuilder(t *testing.T) {

	t.Run("Should build report for namespaced resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-owner",
					Namespace: "qa",
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "replicaset-some-owner",
				Namespace: "qa",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "apps/v1",
						Kind:               "ReplicaSet",
						Name:               "some-owner",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(false),
					},
				},
				Labels: map[string]string{
					starboard.LabelResourceKind:      "ReplicaSet",
					starboard.LabelResourceName:      "some-owner",
					starboard.LabelResourceNamespace: "qa",
					starboard.LabelResourceSpecHash:  "xyz",
					starboard.LabelPluginConfigHash:  "nop",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})

	t.Run("Should build report for cluster scoped resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "system:controller:node-controller",
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			GetClusterReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-6f69bb5b79",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "rbac.authorization.k8s.io/v1",
						Kind:               "ClusterRole",
						Name:               "system:controller:node-controller",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(false),
					},
				},
				Labels: map[string]string{
					starboard.LabelResourceKind:      "ClusterRole",
					starboard.LabelResourceNameHash:  "6f69bb5b79",
					starboard.LabelResourceNamespace: "",
					starboard.LabelResourceSpecHash:  "xyz",
					starboard.LabelPluginConfigHash:  "nop",
				},
				Annotations: map[string]string{
					starboard.LabelResourceName: "system:controller:node-controller",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})
}

type testPlugin struct {
	configHash string
}

func (p *testPlugin) SupportedKinds() []kube.Kind {
	return []kube.Kind{}
}

func (p *testPlugin) IsApplicable(_ starboard.PluginContext, _ client.Object) (bool, string, error) {
	return true, "", nil
}

func (p *testPlugin) Init(_ starboard.PluginContext) error {
	return nil
}

func (p *testPlugin) GetScanJobSpec(_ starboard.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	return corev1.PodSpec{}, nil, nil
}

func (p *testPlugin) ParseConfigAuditReportData(_ starboard.PluginContext, logsReader io.ReadCloser) (v1alpha1.ConfigAuditReportData, error) {
	return v1alpha1.ConfigAuditReportData{}, nil
}

func (p *testPlugin) GetContainerName() string {
	return ""
}

func (p *testPlugin) ConfigHash(_ starboard.PluginContext, _ kube.Kind) (string, error) {
	return p.configHash, nil
}

func TestScanJobBuilder(t *testing.T) {

	t.Run("Should build scan job for resource with simple name", func(t *testing.T) {
		g := NewGomegaWithT(t)
		job, _, err := configauditreport.NewScanJobBuilder().
			WithPlugin(&testPlugin{
				configHash: "hash-test",
			}).
			WithPluginContext(starboard.NewPluginContext().
				WithName("plugin-test").
				WithNamespace("starboard-ns").
				WithServiceAccountName("starboard-sa").
				Get()).
			WithTimeout(3 * time.Second).
			WithObject(&appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-6799fc88d8",
					Namespace: "prod-ns",
				},
			}).
			Get()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(job).To(Equal(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scan-configauditreport-64d65c457",
				Namespace: "starboard-ns",
				Labels: map[string]string{
					starboard.LabelResourceSpecHash:         "755877d4bb",
					starboard.LabelPluginConfigHash:         "hash-test",
					starboard.LabelConfigAuditReportScanner: "plugin-test",
					starboard.LabelK8SAppManagedBy:          "starboard",
					starboard.LabelResourceKind:             "ReplicaSet",
					starboard.LabelResourceName:             "nginx-6799fc88d8",
					starboard.LabelResourceNamespace:        "prod-ns",
				},
			},
			Spec: batchv1.JobSpec{
				BackoffLimit:          pointer.Int32Ptr(0),
				Completions:           pointer.Int32Ptr(1),
				ActiveDeadlineSeconds: pointer.Int64Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							starboard.LabelResourceSpecHash:         "755877d4bb",
							starboard.LabelPluginConfigHash:         "hash-test",
							starboard.LabelConfigAuditReportScanner: "plugin-test",
							starboard.LabelK8SAppManagedBy:          "starboard",
							starboard.LabelResourceKind:             "ReplicaSet",
							starboard.LabelResourceName:             "nginx-6799fc88d8",
							starboard.LabelResourceNamespace:        "prod-ns",
						},
					},
					Spec: corev1.PodSpec{},
				},
			},
		}))
	})

	t.Run("Should build scan job for resource with special name", func(t *testing.T) {
		g := NewGomegaWithT(t)
		job, _, err := configauditreport.NewScanJobBuilder().
			WithPlugin(&testPlugin{
				configHash: "hash-test",
			}).
			WithPluginContext(starboard.NewPluginContext().
				WithName("plugin-test").
				WithNamespace("starboard-ns").
				WithServiceAccountName("starboard-sa").
				Get()).
			WithTimeout(3 * time.Second).
			WithObject(&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "system:controller:node-controller",
				},
			}).
			Get()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(job).NotTo(BeNil())
		b, err := json.Marshal(job)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(b))
		g.Expect(job).To(Equal(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scan-configauditreport-5bfbdd65c9",
				Namespace: "starboard-ns",
				Labels: map[string]string{
					starboard.LabelResourceSpecHash:         "66f8596c77",
					starboard.LabelPluginConfigHash:         "hash-test",
					starboard.LabelConfigAuditReportScanner: "plugin-test",
					starboard.LabelK8SAppManagedBy:          "starboard",
					starboard.LabelResourceKind:             "ClusterRole",
					starboard.LabelResourceNameHash:         "6f69bb5b79",
					starboard.LabelResourceNamespace:        "",
				},
				Annotations: map[string]string{
					starboard.LabelResourceName: "system:controller:node-controller",
				},
			},
			Spec: batchv1.JobSpec{
				BackoffLimit:          pointer.Int32Ptr(0),
				Completions:           pointer.Int32Ptr(1),
				ActiveDeadlineSeconds: pointer.Int64Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							starboard.LabelResourceSpecHash:         "66f8596c77",
							starboard.LabelPluginConfigHash:         "hash-test",
							starboard.LabelConfigAuditReportScanner: "plugin-test",
							starboard.LabelK8SAppManagedBy:          "starboard",
							starboard.LabelResourceKind:             "ClusterRole",
							starboard.LabelResourceNameHash:         "6f69bb5b79",
							starboard.LabelResourceNamespace:        "",
						},
						Annotations: map[string]string{
							starboard.LabelResourceName: "system:controller:node-controller",
						},
					},
					Spec: corev1.PodSpec{},
				},
			},
		}))
	})
}
