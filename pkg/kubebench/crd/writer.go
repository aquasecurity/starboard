package crd

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned/typed/aquasecurity/v1alpha1"
	"k8s.io/klog"

	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/aquasecurity/starboard/pkg/kube"

	core "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ReadWriter struct {
	reports v1alpha1.CISKubeBenchReportInterface
}

func NewReadWriter(clientset starboardapi.Interface) *ReadWriter {
	return &ReadWriter{
		reports: clientset.AquasecurityV1alpha1().CISKubeBenchReports(),
	}
}

func (w *ReadWriter) Write(ctx context.Context, report starboard.CISKubeBenchOutput, node *core.Node) error {
	reportExisting, err := w.reports.Get(ctx, node.Name, meta.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		klog.V(3).Infof("Creating CISKubeBenchReport for %s node", node.Name)
		_, err = w.reports.Create(ctx, &starboard.CISKubeBenchReport{
			ObjectMeta: meta.ObjectMeta{
				Name: node.Name,
				Labels: map[string]string{
					kube.LabelResourceKind:  string(kube.KindNode),
					kube.LabelResourceName:  node.Name,
					kube.LabelHistoryLatest: "true",
				},
				OwnerReferences: []meta.OwnerReference{
					{
						APIVersion: "v1",
						Kind:       string(kube.KindNode),
						Name:       node.Name,
						UID:        node.UID,
						Controller: pointer.BoolPtr(false),
					},
				},
			},
			Report: report,
		}, meta.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	klog.V(3).Infof("Updating existing CISKubeBenchReport for %s node", node.Name)
	reportCopied := reportExisting.DeepCopy()
	reportCopied.Report = report
	_, err = w.reports.Update(ctx, reportCopied, meta.UpdateOptions{})
	return err
}

func (w *ReadWriter) Read(ctx context.Context, node kube.Object) (starboard.CISKubeBenchOutput, error) {
	report, err := w.reports.Get(ctx, node.Name, meta.GetOptions{})
	if err != nil {
		return starboard.CISKubeBenchOutput{}, err
	}
	return report.Report, nil
}
