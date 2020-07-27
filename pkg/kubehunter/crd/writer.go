package crd

import (
	"context"
	"errors"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

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

func (w *writer) Write(ctx context.Context, report starboard.KubeHunterOutput, cluster string) error {
	if strings.TrimSpace(cluster) == "" {
		return errors.New("cluster name must not be blank")
	}
	_, err := w.clientset.AquasecurityV1alpha1().KubeHunterReports().Create(ctx, &starboard.KubeHunterReport{
		ObjectMeta: meta.ObjectMeta{
			Name: cluster,
			Labels: map[string]string{
				kube.LabelResourceKind: "Cluster",
				kube.LabelResourceName: cluster,
			},
		},
		Report: report,
	}, meta.CreateOptions{})
	if err != nil && apierrors.IsAlreadyExists(err) {
		found, err := w.clientset.AquasecurityV1alpha1().KubeHunterReports().Get(ctx, cluster, meta.GetOptions{})
		if err != nil {
			return err
		}
		deepCopy := found.DeepCopy()
		deepCopy.Report = report
		_, err = w.clientset.AquasecurityV1alpha1().KubeHunterReports().Update(ctx, deepCopy, meta.UpdateOptions{})
		return err
	}
	return err
}
