package configauditreport

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type ScanJobBuilder struct {
	plugin             Plugin
	pluginContext      starboard.PluginContext
	timeout            time.Duration
	object             client.Object
	tolerations        []corev1.Toleration
	scanJobAnnotations map[string]string
}

func NewScanJob() *ScanJobBuilder {
	return &ScanJobBuilder{}
}

func (s *ScanJobBuilder) WithPlugin(plugin Plugin) *ScanJobBuilder {
	s.plugin = plugin
	return s
}

func (s *ScanJobBuilder) WithPluginContext(pluginContext starboard.PluginContext) *ScanJobBuilder {
	s.pluginContext = pluginContext
	return s
}

func (s *ScanJobBuilder) WithTimeout(timeout time.Duration) *ScanJobBuilder {
	s.timeout = timeout
	return s
}

func (s *ScanJobBuilder) WithObject(object client.Object) *ScanJobBuilder {
	s.object = object
	return s
}

func (s *ScanJobBuilder) WithTolerations(tolerations []corev1.Toleration) *ScanJobBuilder {
	s.tolerations = tolerations
	return s
}

func (s *ScanJobBuilder) WithScanJobAnnotations(scanJobAnnotations map[string]string) *ScanJobBuilder {
	s.scanJobAnnotations = scanJobAnnotations
	return s
}

func (s *ScanJobBuilder) Get() (*batchv1.Job, []*corev1.Secret, error) {
	jobSpec, secrets, err := s.plugin.GetScanJobSpec(s.pluginContext, s.object)
	if err != nil {
		return nil, nil, err
	}

	podSpecHash, err := kube.ComputeSpecHash(s.object)
	if err != nil {
		return nil, nil, err
	}

	jobSpec.Tolerations = append(jobSpec.Tolerations, s.tolerations...)

	pluginConfigHash, err := s.plugin.GetConfigHash(s.pluginContext)
	if err != nil {
		return nil, nil, err
	}

	labels := map[string]string{
		starboard.LabelResourceKind:             s.object.GetObjectKind().GroupVersionKind().Kind,
		starboard.LabelResourceName:             s.object.GetName(),
		starboard.LabelResourceNamespace:        s.object.GetNamespace(),
		starboard.LabelPodSpecHash:              podSpecHash,
		starboard.LabelPluginConfigHash:         pluginConfigHash,
		starboard.LabelConfigAuditReportScanner: s.pluginContext.GetName(),
		starboard.LabelK8SAppManagedBy:          starboard.AppStarboard,
	}

	for _, secret := range secrets {
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		for k, v := range labels {
			secret.Labels[k] = v
		}
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GetScanJobName(s.object),
			Namespace: s.pluginContext.GetNamespace(),
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.timeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: s.scanJobAnnotations,
				},
				Spec: jobSpec,
			},
		},
	}, secrets, nil
}

func GetScanJobName(obj client.Object) string {
	return fmt.Sprintf("scan-configauditreport-%s", kube.ComputeHash(kube.Object{
		Kind:      kube.Kind(obj.GetObjectKind().GroupVersionKind().Kind),
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}))
}

type ReportBuilder struct {
	scheme           *runtime.Scheme
	controller       metav1.Object
	podSpecHash      string
	pluginConfigHash string
	data             v1alpha1.ConfigAuditReportData
}

func NewReportBuilder(scheme *runtime.Scheme) *ReportBuilder {
	return &ReportBuilder{
		scheme: scheme,
	}
}

func (b *ReportBuilder) Controller(controller metav1.Object) *ReportBuilder {
	b.controller = controller
	return b
}

func (b *ReportBuilder) PodSpecHash(hash string) *ReportBuilder {
	b.podSpecHash = hash
	return b
}

func (b *ReportBuilder) PluginConfigHash(hash string) *ReportBuilder {
	b.pluginConfigHash = hash
	return b
}

func (b *ReportBuilder) Data(data v1alpha1.ConfigAuditReportData) *ReportBuilder {
	b.data = data
	return b
}

func (b *ReportBuilder) reportName() (string, error) {
	kind, err := kube.KindForObject(b.controller, b.scheme)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", strings.ToLower(kind),
		b.controller.GetName()), nil
}

func (b *ReportBuilder) Get() (v1alpha1.ConfigAuditReport, error) {
	kind, err := kube.KindForObject(b.controller, b.scheme)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("getting kind for object: %w", err)
	}

	labels := map[string]string{
		starboard.LabelResourceKind:      kind,
		starboard.LabelResourceName:      b.controller.GetName(),
		starboard.LabelResourceNamespace: b.controller.GetNamespace(),
	}

	if b.podSpecHash != "" {
		labels[starboard.LabelPodSpecHash] = b.podSpecHash
	}

	if b.pluginConfigHash != "" {
		labels[starboard.LabelPluginConfigHash] = b.pluginConfigHash
	}

	reportName, err := b.reportName()
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}

	report := v1alpha1.ConfigAuditReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      reportName,
			Namespace: b.controller.GetNamespace(),
			Labels:    labels,
		},
		Report: b.data,
	}
	err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("setting controller reference: %w", err)
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
