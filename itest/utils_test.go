package itest

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GetNodeNames(ctx context.Context) ([]string, error) {
	nodesList, err := kubernetesClientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	names := make([]string, len(nodesList.Items))
	for i, node := range nodesList.Items {
		names[i] = node.Name
	}
	return names, nil
}
