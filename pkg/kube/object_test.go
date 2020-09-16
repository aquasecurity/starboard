package kube_test

import (
	"errors"
	"testing"

	"github.com/aquasecurity/starboard/pkg/kube"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
)

// TODO Migrate to Ginkgo
func TestObjectFromLabelsSet(t *testing.T) {
	testCases := []struct {
		name           string
		labelsSet      labels.Set
		expectedObject kube.Object
		expectedError  error
	}{
		{
			name: "Should return object for namespaced object",
			labelsSet: labels.Set{
				kube.LabelResourceKind:      "Deployment",
				kube.LabelResourceName:      "my-deployment",
				kube.LabelResourceNamespace: "my-namespace",
			},
			expectedObject: kube.Object{
				Kind:      kube.KindDeployment,
				Name:      "my-deployment",
				Namespace: "my-namespace",
			},
		},
		{
			name: "Should return object for cluster-scoped object",
			labelsSet: labels.Set{
				kube.LabelResourceKind: "Node",
				kube.LabelResourceName: "my-node",
			},
			expectedObject: kube.Object{
				Kind:      kube.KindNode,
				Name:      "my-node",
				Namespace: "",
			},
		},
		{
			name: "Should return error when object kind is not specified as label",
			labelsSet: labels.Set{
				kube.LabelResourceName:      "my-deployment",
				kube.LabelResourceNamespace: "my-namespace",
			},
			expectedError: errors.New("required label does not exist: aquasecurity.github.io/starboard-resource-kind"),
		},
		{
			name: "Should return error when object name is not specified as label",
			labelsSet: labels.Set{
				kube.LabelResourceKind: "Deployment",
			},
			expectedError: errors.New("required label does not exist: aquasecurity.github.io/starboard-resource-name"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obj, err := kube.ObjectFromLabelsSet(tc.labelsSet)
			switch {
			case tc.expectedError == nil:
				require.NoError(t, err)
				assert.Equal(t, tc.expectedObject, obj)
			default:
				assert.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}
}

// TODO Migrate to Ginkgo
func TestContainerImages_AsJSON_And_FromJSON(t *testing.T) {
	containerImages := kube.ContainerImages{
		"nginx": "nginx:1.16",
		"redis": "core.harbor.domain:8443/library/redis:5",
	}
	value, err := containerImages.AsJSON()
	require.NoError(t, err)

	newContainerImages := kube.ContainerImages{}
	err = newContainerImages.FromJSON(value)
	require.NoError(t, err)
	assert.Equal(t, containerImages, newContainerImages)
}

func TestKubePackage(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kube Package Suite")
}

var _ = Describe("Kube package", func() {

	Describe("SetOwnerReference", func() {

		It("should set ownerRef on an empty list", func() {
			rs := &appsv1.ReplicaSet{}
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: "foo-uid"},
			}
			Expect(kube.SetOwnerReference(dep, rs, scheme.Scheme)).ToNot(HaveOccurred())
			Expect(rs.OwnerReferences).To(ConsistOf(metav1.OwnerReference{
				Name:       "foo",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				UID:        "foo-uid",
			}))
		})

		It("should not duplicate owner references", func() {
			rs := &appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							Name:       "foo",
							Kind:       "Deployment",
							APIVersion: "apps/v1",
							UID:        "foo-uid",
						},
					},
				},
			}
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: "foo-uid"},
			}

			Expect(kube.SetOwnerReference(dep, rs, scheme.Scheme)).ToNot(HaveOccurred())
			Expect(rs.OwnerReferences).To(ConsistOf(metav1.OwnerReference{
				Name:       "foo",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				UID:        "foo-uid",
			}))
		})

		It("should update the reference", func() {
			rs := &appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							Name:       "foo",
							Kind:       "Deployment",
							APIVersion: "apps/v1",
							UID:        "foo-uid-1",
						},
					},
				},
			}
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: "foo-uid-2"},
			}

			Expect(kube.SetOwnerReference(dep, rs, scheme.Scheme)).ToNot(HaveOccurred())
			Expect(rs.OwnerReferences).To(ConsistOf(metav1.OwnerReference{
				Name:       "foo",
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				UID:        "foo-uid-2",
			}))

		})
	})

})
