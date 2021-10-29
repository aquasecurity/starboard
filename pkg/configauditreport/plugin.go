package configauditreport

import (
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Plugin defines the interface between Starboard and Kubernetes workload
// configuration checkers / linters / sanitizers.
type Plugin interface {

	// Init is a callback to initialize this plugin, e.g. ensure the default
	// configuration.
	Init(ctx starboard.PluginContext) error

	// GetScanJobSpec describes the pod that will be created by Starboard when
	// it schedules a Kubernetes job to scan the specified workload client.Object.
	// The plugin might return zero to many v1.Secret objects which will be
	// created by Starboard and associated with the scan job.
	GetScanJobSpec(ctx starboard.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error)

	// ParseConfigAuditReportData is a callback to parse and convert logs of
	// the container in a pod controlled by the scan job to v1alpha1.ConfigAuditReportData.
	ParseConfigAuditReportData(ctx starboard.PluginContext, logsReader io.ReadCloser) (v1alpha1.ConfigAuditReportData, error)

	// GetContainerName returns the name of the container in a pod created by a scan job
	// to read logs from.
	GetContainerName() string

	// ConfigHash returns hash of the plugin's configuration settings. The computed hash
	// is used to invalidate v1alpha1.ConfigAuditReport and v1alpha1.ClusterConfigAuditReport
	// objects whenever configuration applicable to the specified resource kind changes.
	ConfigHash(ctx starboard.PluginContext, kind kube.Kind) (string, error)

	// SupportedKinds returns kinds supported by this plugin.
	SupportedKinds() []kube.Kind

	// IsApplicable return true if the given object can be scanned by this
	// plugin, false otherwise.
	IsApplicable(ctx starboard.PluginContext, obj client.Object) (bool, string, error)
}
