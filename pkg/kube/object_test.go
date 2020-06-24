package kube

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
)

func TestObjectFromLabelsSet(t *testing.T) {
	testCases := []struct {
		name           string
		labelsSet      labels.Set
		expectedObject Object
		expectedError  error
	}{
		{
			name: "Should return object for namespaced object",
			labelsSet: labels.Set{
				LabelResourceKind:      "Deployment",
				LabelResourceName:      "my-deployment",
				LabelResourceNamespace: "my-namespace",
			},
			expectedObject: Object{
				Kind:      KindDeployment,
				Name:      "my-deployment",
				Namespace: "my-namespace",
			},
		},
		{
			name: "Should return object for cluster-scoped object",
			labelsSet: labels.Set{
				LabelResourceKind: "Node",
				LabelResourceName: "my-node",
			},
			expectedObject: Object{
				Kind:      KindNode,
				Name:      "my-node",
				Namespace: "",
			},
		},
		{
			name: "Should return error when object kind is not specified as label",
			labelsSet: labels.Set{
				LabelResourceName:      "my-deployment",
				LabelResourceNamespace: "my-namespace",
			},
			expectedError: errors.New("required label does not exist: starboard.resource.kind"),
		},
		{
			name: "Should return error when object name is not specified as label",
			labelsSet: labels.Set{
				LabelResourceKind: "Deployment",
			},
			expectedError: errors.New("required label does not exist: starboard.resource.name"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obj, err := ObjectFromLabelsSet(tc.labelsSet)
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
