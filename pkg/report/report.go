package report

import (
	"io"

	"github.com/aquasecurity/starboard/pkg/kube"
)

type Reporter interface {
	GenerateReport(workload kube.Object, writer io.Writer) error
}
