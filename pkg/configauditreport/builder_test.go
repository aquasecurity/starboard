package configauditreport_test

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
)

func TestBuilder(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	report, err := configauditreport.NewBuilder(scheme.Scheme).
		Controller(&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "some-owner",
				Namespace: "qa",
			},
		}).
		PodSpecHash("xyz").
		PluginConfigHash("nop").
		Result(v1alpha1.ConfigAuditResult{}).Get()

	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(report).To(gomega.Equal(v1alpha1.ConfigAuditReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-some-owner",
			Namespace: "qa",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "ReplicaSet",
					Name:               "some-owner",
					Controller:         pointer.BoolPtr(true),
					BlockOwnerDeletion: pointer.BoolPtr(true),
				},
			},
			Labels: map[string]string{
				"starboard.resource.kind":      "ReplicaSet",
				"starboard.resource.name":      "some-owner",
				"starboard.resource.namespace": "qa",
				"pod-spec-hash":                "xyz",
				"plugin-config-hash":           "nop",
			},
		},
		Report: v1alpha1.ConfigAuditResult{},
	}))
}
