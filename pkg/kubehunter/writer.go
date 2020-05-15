package kubehunter

import (
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Writer interface {
	Write(report starboard.KubeHunterOutput, cluster string) error
}
