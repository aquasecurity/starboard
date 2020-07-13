package report

import (
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/report/templates"
)

type HTMLReporter struct {
	configAudits v1alpha1.ConfigAuditReport
	vulnerabilities v1alpha1.Vulnerability
	savePath string
}

func NewHTMLReporter(configAudits v1alpha1.ConfigAuditReport, vulnerabilities v1alpha1.Vulnerability, savePath string) HTMLReporter {
	return HTMLReporter{
		configAudits: configAudits,
		vulnerabilities: vulnerabilities,
		savePath: savePath,
	}
}

func (h *HTMLReporter) GenerateReport() (htmlReport interface{}, err error) {
	fmt.Printf("%s\n", templates.Hello("Foo"))
	return nil, nil
}

func (h *HTMLReporter) PublishReport(htmlReport interface{}) (err error) {
	return nil
}
