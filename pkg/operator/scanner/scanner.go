package scanner

import (
	"io"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"

	corev1 "k8s.io/api/core/v1"
)

type JobMeta struct {
	Name        string
	Labels      map[string]string
	Annotations map[string]string
}

// Options are arguments passed to the VulnerabilityScanner.GetPodTemplateSpec method.
type Options struct {
	// Namespace the namespace to run the scan Job in.
	Namespace string
	// ServiceAccountName the name of the Service Account to run the Pod controlled by the scan Job.
	ServiceAccountName string
	// ScanJobTimeout scan job timeout.
	ScanJobTimeout time.Duration
}

// VulnerabilityScanner defines methods implemented by vulnerability scanner vendors.
type VulnerabilityScanner interface {

	// GetPodTemplateSpec describes the pod that will be created when executing a scan job
	// for the specified pod descriptor.
	GetPodTemplateSpec(spec corev1.PodSpec, options Options) (corev1.PodTemplateSpec, error)

	// ParseVulnerabilityScanResult is a callback to parse and convert logs of the pod controlled
	// by a scan job to the Starboard model.
	ParseVulnerabilityScanResult(imageRef string, logsReader io.ReadCloser) (
		v1alpha1.VulnerabilityScanResult, error)
}
