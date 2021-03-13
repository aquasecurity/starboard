package configauditreport_test

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
)

func TestBuilder(t *testing.T) {
	report, err := configauditreport.NewBuilder(scheme.Scheme).
		Controller(&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "some-owner",
				Namespace: "qa",
			},
		}).
		PodSpecHash("xyz").
		Result(v1alpha1.ConfigAuditResult{}).Get()

	require.NoError(t, err)
	assert.Equal(t, v1alpha1.ConfigAuditReport{
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
			},
		},
		Report: v1alpha1.ConfigAuditResult{},
	}, report)
}
