package configauditreport

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type Builder interface {
	Owner(owner metav1.Object) Builder
	PodSpecHash(hash string) Builder
	Result(result v1alpha1.ConfigAuditResult) Builder
	Get() (v1alpha1.ConfigAuditReport, error)
}

func NewBuilder(scheme *runtime.Scheme) Builder {
	return &builder{
		scheme: scheme,
	}
}

type builder struct {
	scheme *runtime.Scheme
	owner  metav1.Object
	hash   string
	result v1alpha1.ConfigAuditResult
}

func (b *builder) Owner(owner metav1.Object) Builder {
	b.owner = owner
	return b
}

func (b *builder) PodSpecHash(hash string) Builder {
	b.hash = hash
	return b
}

func (b *builder) Result(result v1alpha1.ConfigAuditResult) Builder {
	b.result = result
	return b
}

func (b *builder) reportName() (string, error) {
	kind, err := kube.KindForObject(b.owner, b.scheme)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", strings.ToLower(kind),
		b.owner.GetName()), nil
}

func (b *builder) Get() (v1alpha1.ConfigAuditReport, error) {
	kind, err := kube.KindForObject(b.owner, b.scheme)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	labels := map[string]string{
		kube.LabelResourceKind:      kind,
		kube.LabelResourceName:      b.owner.GetName(),
		kube.LabelResourceNamespace: b.owner.GetNamespace(),
	}

	if b.hash != "" {
		labels[kube.LabelPodSpecHash] = b.hash
	}

	reportName, err := b.reportName()
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	report := v1alpha1.ConfigAuditReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      reportName,
			Namespace: b.owner.GetNamespace(),
			Labels:    labels,
		},
		Report: b.result,
	}
	err = controllerutil.SetOwnerReference(b.owner, &report, b.scheme)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}
	return report, nil
}
