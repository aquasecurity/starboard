package crd

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned/typed/aquasecurity/v1alpha1"
	"k8s.io/klog"

	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/aquasecurity/starboard/pkg/kube"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ReadWriter struct {
	scheme  *runtime.Scheme
	reports v1alpha1.CISKubeBenchReportInterface
}

func NewReadWriter(scheme *runtime.Scheme, clientset starboardapi.Interface) *ReadWriter {
	return &ReadWriter{
		scheme:  scheme,
		reports: clientset.AquasecurityV1alpha1().CISKubeBenchReports(),
	}
}

func (w *ReadWriter) Write(ctx context.Context, report starboard.CISKubeBenchOutput, node *corev1.Node) error {
	reportExisting, err := w.reports.Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		klog.V(3).Infof("Creating CISKubeBenchReport for %s node", node.Name)
		report := &starboard.CISKubeBenchReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: node.Name,
				Labels: map[string]string{
					kube.LabelResourceKind: string(kube.KindNode),
					kube.LabelResourceName: node.Name,
				},
			},
			Report: report,
		}
		err = controllerutil.SetOwnerReference(node, report, w.scheme)
		if err != nil {
			return err
		}
		_, err = w.reports.Create(ctx, report, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	klog.V(3).Infof("Updating existing CISKubeBenchReport for %s node", node.Name)
	reportCopied := reportExisting.DeepCopy()
	reportCopied.Report = report
	_, err = w.reports.Update(ctx, reportCopied, metav1.UpdateOptions{})
	return err
}

func (w *ReadWriter) Read(ctx context.Context, node kube.Object) (starboard.CISKubeBenchOutput, error) {
	report, err := w.reports.Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		return starboard.CISKubeBenchOutput{}, err
	}
	return report.Report, nil
}
