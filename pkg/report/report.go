package report

import (
	"io"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type WorkloadReporter interface {
	RetrieveData(workload kube.Object) (templates.WorkloadReport, error)
	Generate(workload kube.Object, out io.Writer) error
}

type NamespaceReporter interface {
	RetrieveData(namespace kube.Object) (templates.NamespaceReport, error)
	Generate(namespace kube.Object, out io.Writer) error
}

type NodeReporter interface {
	RetrieveData(node kube.Object) (templates.NodeReport, error)
	Generate(node kube.Object, out io.Writer) error
}
