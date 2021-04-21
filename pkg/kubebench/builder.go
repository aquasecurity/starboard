package kubebench

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type Builder interface {
	Controller(controller metav1.Object) Builder
	Data(data v1alpha1.CISKubeBenchOutput) Builder
	Get() (v1alpha1.CISKubeBenchReport, error)
}

func NewBuilder(scheme *runtime.Scheme) Builder {
	return &builder{
		scheme: scheme,
	}
}

type builder struct {
	scheme     *runtime.Scheme
	controller metav1.Object
	data       v1alpha1.CISKubeBenchOutput
}

func (b *builder) Controller(controller metav1.Object) Builder {
	b.controller = controller
	return b
}

func (b *builder) Data(data v1alpha1.CISKubeBenchOutput) Builder {
	b.data = data
	return b
}

func (b *builder) reportName() string {
	return b.controller.GetName()
}

func (b *builder) Get() (v1alpha1.CISKubeBenchReport, error) {
	kind, err := kube.KindForObject(b.controller, b.scheme)
	if err != nil {
		return v1alpha1.CISKubeBenchReport{}, fmt.Errorf("getting kind for object: %w", err)
	}

	labels := map[string]string{
		starboard.LabelResourceKind: kind,
		starboard.LabelResourceName: b.controller.GetName(),
	}

	reportName := b.reportName()

	report := v1alpha1.CISKubeBenchReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      reportName,
			Namespace: b.controller.GetNamespace(),
			Labels:    labels,
		},
		Report: b.data,
	}
	err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	if err != nil {
		return v1alpha1.CISKubeBenchReport{}, fmt.Errorf("setting controller reference: %w", err)
	}
	// The OwnerReferencesPermissionsEnforcement admission controller protects the
	// access to metadata.ownerReferences[x].blockOwnerDeletion of an object, so
	// that only users with "update" permission to the finalizers subresource of the
	// referenced owner can change it.
	// We set metadata.ownerReferences[x].blockOwnerDeletion to false so that
	// additional RBAC permissions are not required when the OwnerReferencesPermissionsEnforcement
	// is enabled.
	// See https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#ownerreferencespermissionenforcement
	report.OwnerReferences[0].BlockOwnerDeletion = pointer.BoolPtr(false)
	return report, nil
}
