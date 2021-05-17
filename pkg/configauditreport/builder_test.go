package configauditreport_test

import (
	. "github.com/onsi/gomega"

	"io"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/starboard"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestReportBuilder(t *testing.T) {
	g := NewGomegaWithT(t)

	report, err := configauditreport.NewReportBuilder(scheme.Scheme).
		Controller(&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "some-owner",
				Namespace: "qa",
			},
		}).
		PodSpecHash("xyz").
		PluginConfigHash("nop").
		Data(v1alpha1.ConfigAuditResult{}).
		Get()

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
				starboard.LabelPodSpecHash:       "xyz",
				starboard.LabelPluginConfigHash:  "nop",
			},
		},
		Report: v1alpha1.ConfigAuditResult{},
	}))
}

type testPlugin struct {
	configHash string
}

func (p *testPlugin) GetScanJobSpec(ctx starboard.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	return corev1.PodSpec{}, nil, nil
}

func (p *testPlugin) ParseConfigAuditReportData(logsReader io.ReadCloser) (v1alpha1.ConfigAuditResult, error) {
	return v1alpha1.ConfigAuditResult{}, nil
}

func (p *testPlugin) GetContainerName() string {
	return ""
}

func (p *testPlugin) GetConfigHash(ctx starboard.PluginContext) (string, error) {
	return p.configHash, nil
}

func TestScanJobBuilder(t *testing.T) {
	g := NewGomegaWithT(t)
	job, _, err := configauditreport.NewScanJob().
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
	g.Expect(job).NotTo(BeNil())
	g.Expect(job).To(Equal(&batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scan-configauditreport-fcc9884cb",
			Namespace: "starboard-ns",
			Labels: map[string]string{
				starboard.LabelPodSpecHash:              "58b8989656",
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
						starboard.LabelPodSpecHash:              "58b8989656",
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
}
