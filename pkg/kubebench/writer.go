package kubebench

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type Writer interface {
	Write(ctx context.Context, report v1alpha1.CISKubeBenchOutput, node *corev1.Node) error
}

type Reader interface {
	Read(ctx context.Context, node kube.Object) (v1alpha1.CISKubeBenchOutput, error)
}

type ReadWriter interface {
	Writer
	Reader
}

type rw struct {
	scheme *runtime.Scheme
	client versioned.Interface
}

func NewReadWriter(scheme *runtime.Scheme, clientset versioned.Interface) ReadWriter {
	return &rw{
		scheme: scheme,
		client: clientset,
	}
}

func (w *rw) Write(ctx context.Context, report v1alpha1.CISKubeBenchOutput, node *corev1.Node) error {
	reportExisting, err := w.client.AquasecurityV1alpha1().CISKubeBenchReports().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		klog.V(3).Infof("Creating CISKubeBenchReport for %s node", node.Name)
		report := &v1alpha1.CISKubeBenchReport{
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
		_, err = w.client.AquasecurityV1alpha1().CISKubeBenchReports().Create(ctx, report, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	klog.V(3).Infof("Updating existing CISKubeBenchReport for %s node", node.Name)
	reportCopied := reportExisting.DeepCopy()
	reportCopied.Report = report
	_, err = w.client.AquasecurityV1alpha1().CISKubeBenchReports().Update(ctx, reportCopied, metav1.UpdateOptions{})
	return err
}

func (w *rw) Read(ctx context.Context, node kube.Object) (v1alpha1.CISKubeBenchOutput, error) {
	report, err := w.client.AquasecurityV1alpha1().CISKubeBenchReports().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		return v1alpha1.CISKubeBenchOutput{}, err
	}
	return report.Report, nil
}
