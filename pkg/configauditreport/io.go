package configauditreport

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Writer is the interface for saving v1alpha1.ClusterConfigAuditReport
// and v1alpha1.ConfigAuditReport instances.
type Writer interface {

	// SaveReport creates or updates the given v1alpha1.ConfigAuditReport instance.
	SaveReport(ctx context.Context, report v1alpha1.ConfigAuditReport) error

	// SaveClusterReport creates or updates the given v1alpha1.ClusterConfigAuditReport instance.
	SaveClusterReport(ctx context.Context, report v1alpha1.ClusterConfigAuditReport) error
}

// FindOption is some configuration that modifies options for a find request.
type FindOption interface {
	// ApplyTo applies this configuration to the given find options.
	ApplyTo(*FindOptions)
}

// FindOptions contains options for limiting or filtering results.
type FindOptions struct {
	// LabelSelector filters results by label.
	LabelSelector labels.Selector
}

// ApplyOptions applies the given find options on these options,
// and then returns itself (for convenient chaining).
func (o *FindOptions) ApplyOptions(opts []FindOption) *FindOptions {
	for _, opt := range opts {
		opt.ApplyTo(o)
	}
	return o
}

// Reader is the interface that wraps methods for finding v1alpha1.ConfigAuditReport
// and v1alpha1.ClusterConfigAuditReport objects.
// TODO(API): Consider returning starboard.ResourceNotFound error instead of returning nil.
type Reader interface {

	// FindReportByOwner returns a v1alpha1.ConfigAuditReport owned by the given
	// kube.Object or nil if the report is not found.
	FindReportByOwner(ctx context.Context, owner kube.Object, opts ...FindOption) (*v1alpha1.ConfigAuditReport, error)

	// FindReportByOwnerInHierarchy is similar to FindReportByOwner except that it tries to lookup
	// a v1alpha1.ConfigAuditReport object owned by related Kubernetes objects.
	// For example, if the given owner is a Deployment, but a report is owned by the
	// active ReplicaSet (current revision) this method will return the report.
	FindReportByOwnerInHierarchy(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error)

	// FindClusterReportByOwner returns a v1alpha1.ClusterConfigAuditReport owned by the given
	// kube.Object or nil if the report is not found.
	FindClusterReportByOwner(ctx context.Context, owner kube.Object, opts ...FindOption) (*v1alpha1.ClusterConfigAuditReport, error)
}

type ReadWriter interface {
	Writer
	Reader
}

type readWriter struct {
	*kube.ObjectResolver
}

// NewReadWriter constructs a new ReadWriter which is using the client package
// provided by the controller-runtime libraries for interacting with the
// Kubernetes API server.
func NewReadWriter(client client.Client) ReadWriter {
	return &readWriter{
		ObjectResolver: &kube.ObjectResolver{Client: client},
	}
}

func (r *readWriter) SaveReport(ctx context.Context, report v1alpha1.ConfigAuditReport) error {
	var existing v1alpha1.ConfigAuditReport
	err := r.Get(ctx, types.NamespacedName{
		Name:      report.Name,
		Namespace: report.Namespace,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = report.Report

		return r.Update(ctx, copied)
	}

	if errors.IsNotFound(err) {
		return r.Create(ctx, &report)
	}

	return err
}

func (r *readWriter) SaveClusterReport(ctx context.Context, report v1alpha1.ClusterConfigAuditReport) error {
	var existing v1alpha1.ClusterConfigAuditReport
	err := r.Get(ctx, types.NamespacedName{
		Name: report.Name,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = report.Report

		return r.Update(ctx, copied)
	}

	if errors.IsNotFound(err) {
		return r.Create(ctx, &report)
	}

	return err
}

// MatchingLabels filters the find operation on the given set of labels.
type MatchingLabels map[string]string

// ApplyTo applies this configuration to the given find options.
func (m MatchingLabels) ApplyTo(opts *FindOptions) {
	sel := labels.SelectorFromValidatedSet(map[string]string(m))
	opts.LabelSelector = sel
}

func (r *readWriter) FindReportByOwner(ctx context.Context, owner kube.Object, opts ...FindOption) (*v1alpha1.ConfigAuditReport, error) {
	findOpts := &FindOptions{}
	findOpts.ApplyOptions(opts)

	err := r.applyOwnerToFindOptions(findOpts, owner)
	if err != nil {
		return nil, err
	}

	var list v1alpha1.ConfigAuditReportList
	err = r.List(ctx, &list, client.MatchingLabelsSelector{
		Selector: findOpts.LabelSelector,
	}, client.InNamespace(owner.Namespace))
	if err != nil {
		return nil, err
	}

	if len(list.Items) > 0 {
		return &list.DeepCopy().Items[0], nil
	}
	return nil, nil
}

func (r *readWriter) FindReportByOwnerInHierarchy(ctx context.Context, owner kube.Object) (*v1alpha1.ConfigAuditReport, error) {
	report, err := r.FindReportByOwner(ctx, owner)
	if err != nil {
		return nil, err
	}

	// no reports found for provided owner, look for reports in related replicaset
	if report == nil && (owner.Kind == kube.KindDeployment || owner.Kind == kube.KindPod) {
		rsName, err := r.GetRelatedReplicasetName(ctx, owner)
		if err != nil {
			return nil, fmt.Errorf("getting replicaset related to %s/%s: %w", owner.Kind, owner.Name, err)
		}
		report, err = r.FindReportByOwner(ctx, kube.Object{
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

func (r *readWriter) FindClusterReportByOwner(ctx context.Context, owner kube.Object, opts ...FindOption) (*v1alpha1.ClusterConfigAuditReport, error) {
	findOpts := &FindOptions{}
	findOpts.ApplyOptions(opts)

	err := r.applyOwnerToFindOptions(findOpts, owner)
	if err != nil {
		return nil, err
	}

	var list v1alpha1.ClusterConfigAuditReportList
	err = r.List(ctx, &list, client.MatchingLabelsSelector{
		Selector: findOpts.LabelSelector,
	})
	if err != nil {
		return nil, err
	}

	if len(list.Items) > 0 {
		return &list.DeepCopy().Items[0], nil
	}
	return nil, nil
}

func (r *readWriter) applyOwnerToFindOptions(findOpts *FindOptions, owner kube.Object) error {
	if findOpts.LabelSelector == nil {
		findOpts.LabelSelector = labels.Everything()
	}

	requirements, err := r.objectToRequirements(owner)
	if err != nil {
		return err
	}

	findOpts.LabelSelector.Add(requirements...)
	return nil
}

func (r *readWriter) objectToRequirements(owner kube.Object) ([]labels.Requirement, error) {
	var requirements []labels.Requirement

	kindReq, err := labels.NewRequirement(starboard.LabelResourceKind, selection.Equals, []string{string(owner.Kind)})
	if err != nil {
		return nil, err
	}
	requirements = append(requirements, *kindReq)

	nameReq, err := labels.NewRequirement(starboard.LabelResourceName, selection.Equals, []string{owner.Name})
	if err != nil {
		return nil, err
	}
	requirements = append(requirements, *nameReq)

	if owner.Namespace != "" {
		namespaceReq, err := labels.NewRequirement(starboard.LabelResourceNamespace, selection.Equals, []string{owner.Namespace})
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, *namespaceReq)
	}

	return requirements, nil
}
