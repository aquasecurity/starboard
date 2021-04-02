package kubebench

import (
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
)

// Plugin defines the interface between Starboard and Kubernetes configuration
// checker with CIS Kubernetes Benchmarks.
type Plugin interface {

	// GetScanJobSpec describes the pod that will be created by Starboard when
	// it schedules a Kubernetes job to audit the configuration of the specified
	// node.
	GetScanJobSpec(ctx starboard.PluginContext, node corev1.Node) (corev1.PodSpec, error)

	// ParseCISKubeBenchOutput is a callback to parse and convert logs of
	// the pod controlled by the scan job to v1alpha1.CISKubeBenchOutput.
	ParseCISKubeBenchOutput(logsStream io.ReadCloser) (v1alpha1.CISKubeBenchOutput, error)

	GetContainerName() string
}
