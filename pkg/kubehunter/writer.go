package kubehunter

import (
	sec "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Writer interface {
	Write(report sec.KubeHunterOutput, cluster string) error
}
