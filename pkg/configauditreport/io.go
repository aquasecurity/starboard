package configauditreport

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard/pkg/kube"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Writer is the interface that wraps the basic Write method.
//
// Write creates or updates the given v1alpha1.ConfigAuditReport instance.
type Writer interface {
	Write(ctx context.Context, report v1alpha1.ConfigAuditReport) error
}

// Reader is the interface that wraps basic FindByOwner method.
//
// FindByOwner returns a v1alpha1.ConfigAuditReport owned by the given
// kube.Object or nil if the report is not found.
type Reader interface {
	FindByOwner(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error)
}

type ReadWriter interface {
	Writer
	Reader
}

type readWriter struct {
	clientset versioned.Interface
}

// NewReadWriter constructs a new ReadWriter which is using the client-go
// module for interacting with the Kubernetes API server.
func NewReadWriter(clientset versioned.Interface) ReadWriter {
	return &readWriter{
		clientset: clientset,
	}
}

func (r *readWriter) Write(ctx context.Context, report v1alpha1.ConfigAuditReport) error {
	existing, err := r.clientset.AquasecurityV1alpha1().ConfigAuditReports(report.Namespace).
		Get(ctx, report.Name, metav1.GetOptions{})

	if err == nil {
		klog.V(3).Infof("Updating ConfigAuditReport %q", report.Namespace+"/"+report.Name)
		deepCopy := existing.DeepCopy()
		deepCopy.Labels = report.Labels
		deepCopy.Report = report.Report

		_, err = r.clientset.AquasecurityV1alpha1().ConfigAuditReports(report.Namespace).
			Update(ctx, deepCopy, metav1.UpdateOptions{})
		return err
	}

	if errors.IsNotFound(err) {
		klog.V(3).Infof("Creating ConfigAuditReport %q", report.Namespace+"/"+report.Name)
		_, err = r.clientset.AquasecurityV1alpha1().ConfigAuditReports(report.Namespace).
			Create(ctx, &report, metav1.CreateOptions{})
		return err
	}

	return err
}

func (r *readWriter) FindByOwner(ctx context.Context, workload kube.Object) (*v1alpha1.ConfigAuditReport, error) {
	list, err := r.clientset.AquasecurityV1alpha1().ConfigAuditReports(workload.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{
			kube.LabelResourceKind:      string(workload.Kind),
			kube.LabelResourceName:      workload.Name,
			kube.LabelResourceNamespace: workload.Namespace,
		}.String(),
	})
	if err != nil {
		return nil, err
	}
	// Only one config audit per specific workload exists on the cluster
	if len(list.Items) > 0 {
		return &list.DeepCopy().Items[0], nil
	}
	return nil, nil
}

type crReadWriter struct {
	client client.Client
}

// NewControllerRuntimeReadWriter constructs a new ReadWriter which is
// using the client package provided by the controller-runtime libraries for
// interacting with the Kubernetes API server.
func NewControllerRuntimeReadWriter(client client.Client) ReadWriter {
	return &crReadWriter{
		client: client,
	}
}

func (r *crReadWriter) Write(ctx context.Context, report v1alpha1.ConfigAuditReport) error {
	var existing v1alpha1.ConfigAuditReport
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      report.Name,
		Namespace: report.Namespace,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = report.Report

		return r.client.Update(ctx, copied)
	}

	if errors.IsNotFound(err) {
		return r.client.Create(ctx, &report)
	}

	return err
}

func (r *crReadWriter) FindByOwner(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error) {
	var list v1alpha1.ConfigAuditReportList

	err := r.client.List(ctx, &list, client.MatchingLabels{
		kube.LabelResourceKind:      string(owner.Kind),
		kube.LabelResourceNamespace: owner.Namespace,
		kube.LabelResourceName:      owner.Name,
	}, client.InNamespace(owner.Namespace))
	if err != nil {
		return nil, err
	}

	// Only one config audit per specific workload exists on the cluster
	if len(list.Items) > 0 {
		return &list.DeepCopy().Items[0], nil
	}
	return nil, nil
}
