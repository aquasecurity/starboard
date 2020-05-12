package kubebench

import (
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	core "k8s.io/api/core/v1"
)

type Writer interface {
	Write(report starboard.CISKubernetesBenchmarkReport, node *core.Node) error
}
