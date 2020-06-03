package crd

import (
	"context"
	"errors"
	"strings"

	"github.com/aquasecurity/starboard/pkg/kube"

	"github.com/aquasecurity/starboard/pkg/kubehunter"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type writer struct {
	clientset starboardapi.Interface
}

func NewWriter(clientset starboardapi.Interface) kubehunter.Writer {
	return &writer{
		clientset: clientset,
	}

}

func (w *writer) Write(ctx context.Context, report starboard.KubeHunterOutput, cluster string) (err error) {
	if strings.TrimSpace(cluster) == "" {
		err = errors.New("cluster name must not be blank")
		return
	}
	// TODO Check if an instance of the report with the given name already exists.
	// TODO If exists just update it, create new instance otherwise
	_, err = w.clientset.AquasecurityV1alpha1().KubeHunterReports().Create(ctx, &starboard.KubeHunterReport{
		ObjectMeta: meta.ObjectMeta{
			Name: cluster,
			Labels: map[string]string{
				kube.LabelResourceKind: "Cluster",
				kube.LabelResourceName: cluster,
			},
		},
		Report: report,
	}, meta.CreateOptions{})
	return
}
