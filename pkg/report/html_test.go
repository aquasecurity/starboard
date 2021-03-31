package report

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/report/templates"

	"k8s.io/utils/pointer"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

var (
	sampleVulnsReports = []starboard.VulnerabilityReport{
		{
			Report: starboard.VulnerabilityScanResult{
				Scanner: starboard.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "0.9.1",
				},
				Registry: starboard.Registry{
					Server: "index.docker.io",
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
				Vulnerabilities: []starboard.Vulnerability{
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
				}},
		}}
	sampleConfigAudits = []starboard.ConfigAuditReport{
		{
			Report: starboard.ConfigAuditResult{

				Scanner: starboard.Scanner{
					Name:    "Polaris",
					Vendor:  "Fairwinds",
					Version: "latest",
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
	t.Skip("Fix me - think of a better idea to test html report thoroughly enough")
	//var workload = kube.Object{
	//	Name: "csp-database",
	//	Namespace: "aqua",
	//	Kind: "Deployment",
	//}
	//assert.Contains(t, htmlReportStr, "cpuRequestsMissing")
	//assert.Contains(t, htmlReportStr, "1.1.1c-r0")
	//assert.Contains(t, htmlReportStr, "Trivy")
	//assert.Contains(t, htmlReportStr, "index.docker.io")
}

func Test_topNVulnerabilitiesByScore(t *testing.T) {
	testCases := []struct {
		name           string
		reports        []v1alpha1.VulnerabilityReport
		expectedOutput []templates.VulnerabilityWithCount
	}{
		{
			name: "Should return top 5 vulnerabilities with count",
			reports: []starboard.VulnerabilityReport{
				{
					Report: starboard.VulnerabilityScanResult{
						Vulnerabilities: []starboard.Vulnerability{
							{
								VulnerabilityID: "CVE-2019-1549",
								Severity:        starboard.SeverityCritical,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1549",
								Score:           pointer.Float64Ptr(8.2),
							},
							{
								VulnerabilityID: "CVE-2019-1547",
								Severity:        starboard.SeverityLow,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
								Score:           pointer.Float64Ptr(6.3),
							},
							{
								VulnerabilityID: "CVE-2011-3374",
								Severity:        starboard.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.7),
							},
						},
					},
				},
				{
					Report: starboard.VulnerabilityScanResult{
						Vulnerabilities: []starboard.Vulnerability{
							{
								VulnerabilityID: "CVE-2019-1548",
								Severity:        starboard.SeverityCritical,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1548",
								Score:           pointer.Float64Ptr(9.1),
							},
							{
								VulnerabilityID: "CVE-2019-1547",
								Severity:        starboard.SeverityLow,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
								Score:           pointer.Float64Ptr(6.3),
							},
							{
								VulnerabilityID: "CVE-2020-27350",
								Severity:        starboard.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2020-27350",
								Score:           pointer.Float64Ptr(5.7),
							},
							{
								VulnerabilityID: "CVE-2011-3374",
								Severity:        starboard.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.7),
							},
							{
								VulnerabilityID: "CVE-2011-3375",
								Severity:        starboard.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.6),
							},
						},
					},
				},
			},
			expectedOutput: []templates.VulnerabilityWithCount{
				{
					Vulnerability: starboard.Vulnerability{
						VulnerabilityID: "CVE-2019-1548",
						Severity:        starboard.SeverityCritical,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1548",
						Score:           pointer.Float64Ptr(9.1),
					},
					AffectedWorkloads: 1,
				},
				{
					Vulnerability: starboard.Vulnerability{
						VulnerabilityID: "CVE-2019-1549",
						Severity:        starboard.SeverityCritical,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1549",
						Score:           pointer.Float64Ptr(8.2),
					},
					AffectedWorkloads: 1,
				},
				{
					Vulnerability: starboard.Vulnerability{
						VulnerabilityID: "CVE-2019-1547",
						Severity:        starboard.SeverityLow,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
						Score:           pointer.Float64Ptr(6.3),
					},
					AffectedWorkloads: 2,
				},
				{
					Vulnerability: starboard.Vulnerability{
						VulnerabilityID: "CVE-2020-27350",
						Severity:        starboard.SeverityMedium,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2020-27350",
						Score:           pointer.Float64Ptr(5.7),
					},
					AffectedWorkloads: 1,
				},
				{
					Vulnerability: starboard.Vulnerability{
						VulnerabilityID: "CVE-2011-3374",
						Severity:        starboard.SeverityMedium,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
						Score:           pointer.Float64Ptr(3.7),
					},
					AffectedWorkloads: 2,
				},
			},
		},
		{
			name: "Should return 2 vulnerabilities with count when some input has nil scores",
			reports: []starboard.VulnerabilityReport{
				{
					Report: starboard.VulnerabilityScanResult{
						Vulnerabilities: []starboard.Vulnerability{
							{
								VulnerabilityID: "CVE-2019-1549",
								Severity:        starboard.SeverityCritical,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1549",
								Score:           pointer.Float64Ptr(8.2),
							},
							{
								VulnerabilityID: "CVE-2019-1547",
								Severity:        starboard.SeverityLow,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
								Score:           nil,
							},
							{
								VulnerabilityID: "CVE-2011-3374",
								Severity:        starboard.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.7),
							},
						},
					},
				},
				{
					Report: starboard.VulnerabilityScanResult{
						Vulnerabilities: []starboard.Vulnerability{
							{
								VulnerabilityID: "CVE-2019-1548",
								Severity:        starboard.SeverityCritical,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1548",
								Score:           nil,
							},
							{
								VulnerabilityID: "CVE-2019-1547",
								Severity:        starboard.SeverityLow,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
								Score:           nil,
							},
							{
								VulnerabilityID: "CVE-2020-27350",
								Severity:        starboard.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2020-27350",
								Score:           nil,
							},
							{
								VulnerabilityID: "CVE-2011-3374",
								Severity:        starboard.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.7),
							},
						},
					},
				},
			},
			expectedOutput: []templates.VulnerabilityWithCount{
				{
					Vulnerability: starboard.Vulnerability{
						VulnerabilityID: "CVE-2019-1549",
						Severity:        starboard.SeverityCritical,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1549",
						Score:           pointer.Float64Ptr(8.2),
					},
					AffectedWorkloads: 1,
				},
				{
					Vulnerability: starboard.Vulnerability{
						VulnerabilityID: "CVE-2011-3374",
						Severity:        starboard.SeverityMedium,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
						Score:           pointer.Float64Ptr(3.7),
					},
					AffectedWorkloads: 2,
				},
			},
		},
	}

	for _, tc := range testCases {
		r := namespaceReporter{}
		t.Run(tc.name, func(t *testing.T) {
			vulWithCount := r.topNVulnerabilitiesByScore(tc.reports, 5)
			assert.Equal(t, tc.expectedOutput, vulWithCount)
		})
	}
}
