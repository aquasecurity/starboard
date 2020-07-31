package report

import (
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	sampleVulnsReports = []starboard.Vulnerability{
		{
			Report: starboard.VulnerabilityReport{
				Scanner: starboard.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "0.9.1",
				},
				Registry: starboard.Registry{
					URL: "index.docker.io",
				},
				Artifact: starboard.Artifact{
					Repository: "library/alpine",
					Tag:        "3.10.2",
				},
				Summary: starboard.VulnerabilitySummary{
					CriticalCount: 0,
					MediumCount:   1,
					LowCount:      1,
					NoneCount:     0,
					UnknownCount:  0,
				},
				Vulnerabilities: []starboard.VulnerabilityItem{
					{
						VulnerabilityID:  "CVE-2019-1549",
						Resource:         "openssl",
						InstalledVersion: "1.1.1c-r0",
						FixedVersion:     "1.1.1d-r0",
						Severity:         starboard.SeverityMedium,
						Title:            "openssl: information disclosure in fork()",
						Links: []string{
							"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549",
						},
					},
					{
						VulnerabilityID:  "CVE-2019-1547",
						Resource:         "openssl",
						InstalledVersion: "1.1.1c-r0",
						FixedVersion:     "1.1.1d-r0",
						Severity:         starboard.SeverityLow,
						Title:            "openssl: side-channel weak encryption vulnerability",
						Links: []string{
							"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
						},
					},
				},},
		}}
	sampleConfigAudits = []starboard.ConfigAuditReport{
		{
			Report: starboard.ConfigAudit {

				Scanner: starboard.Scanner{
					Name:    "Polaris",
					Vendor:  "Fairwinds",
					Version: "latest",
				},
				Resource: starboard.KubernetesNamespacedResource{
					Namespace: "aqua",
					KubernetesResource: starboard.KubernetesResource{
						Kind: "Deployment",
						Name: "csp-database",
					},
				},
				PodChecks: []starboard.Check{
					{
						ID:       "hostIPCSet",
						Message:  "Host IPC is not configured",
						Success:  true,
						Severity: "error",
						Category: "Security",
					},
					{
						ID:       "hostNetworkSet",
						Message:  "Host network is not configured",
						Success:  true,
						Severity: "warning",
						Category: "Networking",
					},
				},
				ContainerChecks: map[string][]starboard.Check{
					"db": {
						{
							ID:       "cpuLimitsMissing",
							Message:  "CPU limits are set",
							Success:  true,
							Severity: "warning",
							Category: "Resources",
						},
						{
							ID:       "cpuRequestsMissing",
							Message:  "CPU requests are set",
							Success:  true,
							Severity: "warning",
							Category: "Resources",
						},
					},
				},
			},
		}}
)

func TestHTMLReporter_GenerateReport(t *testing.T) {
	var workload = kube.Object{
		Name: "csp-database",
		Namespace: "aqua",
		Kind: "Deployment",
	}
	reporter := NewHTMLReporter(sampleConfigAudits, sampleVulnsReports, workload)
	htmlReport, err := reporter.GenerateReport()
	require.NoError(t, err)
	htmlReportStr := string(htmlReport)
	assert.Contains(t, htmlReportStr, "cpuRequestsMissing")
	assert.Contains(t, htmlReportStr, "1.1.1c-r0")
	assert.Contains(t, htmlReportStr, "Trivy")
	assert.Contains(t, htmlReportStr, "index.docker.io")
}