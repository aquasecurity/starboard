package configauditreport

import (
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Plugin defines the interface between Starboard and Kubernetes workload
// configuration checkers / linters / sanitizers. Not a final version, rather
// first step to separate generic workloads discovery code and Polaris
// implementation details.
type Plugin interface {
	GetScanJobSpec(workload kube.Object, gvk schema.GroupVersionKind) (corev1.PodSpec, error)

	GetContainerName() string

	ParseConfigAuditResult(logsReader io.ReadCloser) (v1alpha1.ConfigAuditResult, error)
}
