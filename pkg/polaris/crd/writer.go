package crd

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/labels"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	clientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/polaris"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

type writer struct {
	client clientset.Interface
}

func NewWriter(client clientset.Interface) polaris.Writer {
	return &writer{
		client: client,
	}
}

func (w *writer) Write(ctx context.Context, report starboard.ConfigAudit) (err error) {
	namespace := report.Resource.Namespace
	name := fmt.Sprintf("%s.%s", strings.ToLower(report.Resource.Kind), report.Resource.Name)

	existingCR, err := w.client.AquasecurityV1alpha1().ConfigAuditReports(namespace).Get(ctx, name, meta.GetOptions{})

	switch {
	case err == nil:
		klog.V(3).Infof("Updating config audit report: %s/%s", namespace, name)
		deepCopy := existingCR.DeepCopy()
		deepCopy.Report = report
		_, err = w.client.AquasecurityV1alpha1().ConfigAuditReports(namespace).Update(ctx, deepCopy, meta.UpdateOptions{})
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating config audit report: %s/%s", namespace, name)
		_, err = w.client.AquasecurityV1alpha1().ConfigAuditReports(namespace).
			Create(ctx, &starboard.ConfigAuditReport{
				ObjectMeta: meta.ObjectMeta{
					Name: name,
					Labels: labels.Set{
						kube.LabelResourceKind: report.Resource.Kind,
						kube.LabelResourceName: report.Resource.Name,
					},
				},
				Report: report,
			}, meta.CreateOptions{})
		return
	}
	return
}

func (w *writer) WriteAll(ctx context.Context, reports []starboard.ConfigAudit) (err error) {
	for _, report := range reports {
		err = w.Write(ctx, report)
	}
	return
}
