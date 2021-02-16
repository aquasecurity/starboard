package configauditreport

import (
	"context"
	"fmt"
	"k8s.io/client-go/kubernetes"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kube/rs"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Writer is the interface that wraps the basic Write method.
//
// Write creates or updates the given v1alpha1.ConfigAuditReport instance.
type Writer interface {
	Write(ctx context.Context, report v1alpha1.ConfigAuditReport) error
}

// Reader is the interface that wraps methods for finding v1alpha1.ConfigAuditReport objects.
//
// FindByOwner returns a v1alpha1.ConfigAuditReport owned by the given
// kube.Object or nil if the report is not found.
//
// FindByOwnerInHierarchy is similar to FindByOwner except that it tries to lookup
// the v1alpha1.ConfigAuditReport objects owned by related Kubernetes objects.
// For example, if the given owner is a Deployment, but a report is owned
// by the active ReplicaSet (current revision) this method will return the report.
type Reader interface {
	FindByOwner(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error)
	FindByOwnerInHierarchy(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error)
}

type ReadWriter interface {
	Writer
	Reader
}

type readWriter struct {
	client client.Client
	// TODO Get rid of it once we refactor ReplicaSet resolver
	clientset kubernetes.Interface
}

// NewReadWriter constructs a new ReadWriter which is using the client package
// provided by the controller-runtime libraries for interacting with the
// Kubernetes API server.
func NewReadWriter(client client.Client, clientset kubernetes.Interface) ReadWriter {
	return &readWriter{
		client:    client,
		clientset: clientset,
	}
}

func (r *readWriter) Write(ctx context.Context, report v1alpha1.ConfigAuditReport) error {
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

func (r *readWriter) FindByOwner(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error) {
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

func (r *readWriter) FindByOwnerInHierarchy(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error) {
	report, err := r.FindByOwner(ctx, owner)
	if err != nil {
		return nil, err
	}

	// no reports found for provided owner, look for reports in related replicaset
	if report == nil && (owner.Kind == kube.KindDeployment || owner.Kind == kube.KindPod) {
		rsName, err := rs.GetRelatedReplicasetName(ctx, owner, r.clientset)
		if err != nil {
			return nil, fmt.Errorf("getting replicaset related to %s/%s: %w", owner.Kind, owner.Name, err)
		}
		report, err = r.FindByOwner(ctx, kube.Object{
			Kind:      kube.KindReplicaSet,
			Name:      rsName,
			Namespace: owner.Namespace,
		})

	}

	if report != nil {
		return report.DeepCopy(), nil
	}
	return nil, nil
}
