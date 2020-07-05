package trivy

import (
	"fmt"
	"strings"
	"testing"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	sampleReportAsString = `[
	{
		"Target": "alpine:3.10.2 (alpine 3.10.2)",
		"Type": "alpine",
		"Vulnerabilities": [
		{
			"VulnerabilityID": "CVE-2019-1549",
			"PkgName": "openssl",
			"InstalledVersion": "1.1.1c-r0",
			"FixedVersion": "1.1.1d-r0",
			"Title": "openssl: information disclosure in fork()",
			"Severity": "MEDIUM",
			"References": [
				"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549"
		]
		},
		{
			"VulnerabilityID": "CVE-2019-1547",
			"PkgName": "openssl",
			"InstalledVersion": "1.1.1c-r0",
			"FixedVersion": "1.1.1d-r0",
			"Title": "openssl: side-channel weak encryption vulnerability",
			"Severity": "LOW",
			"References": [
				"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547"
		]
		}
	]
	}
]`

	sampleReport = starboard.VulnerabilityReport{
		Scanner: starboard.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: "0.9.1",
		},
		Artifact: starboard.Artifact{
			Repository: "library/alpine",
			Tag:        "3.12",
		},
		Registry: starboard.Registry{
			URL: "index.docker.io",
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
		},
	}
)

func TestConverter_Convert(t *testing.T) {

	testCases := []struct {
		name           string
		input          string
		imageRef       string
		expectedError  error
		expectedReport starboard.VulnerabilityReport
	}{
		{
			name: "Should convert vulnerability report in JSON format when input is noisy",
			input: fmt.Sprintf("2020-06-17T23:37:45.320+0200	[34mINFO[0m	Detecting Alpine vulnerabilities...\n%s", sampleReportAsString),
			imageRef:       "alpine:3.12",
			expectedError:  nil,
			expectedReport: sampleReport,
		},
		{
			name:           "Should convert vulnerability report in JSON format when input is quiet",
			input:          sampleReportAsString,
			imageRef:       "alpine:3.12",
			expectedError:  nil,
			expectedReport: sampleReport,
		},
		{
			name: "Should convert vulnerability report in JSON format when OS is not detected",
			input: `2020-06-21T23:10:15.162+0200	WARN	OS is not detected and vulnerabilities in OS packages are not detected.
null`,
			imageRef:      "alpine:3.12",
			expectedError: nil,
			expectedReport: starboard.VulnerabilityReport{
				Scanner: starboard.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "0.9.1",
				},
				Artifact: starboard.Artifact{
					Repository: "library/alpine",
					Tag:        "3.12",
				},
				Registry: starboard.Registry{
					URL: "index.docker.io",
				},
				Summary: starboard.VulnerabilitySummary{
					CriticalCount: 0,
					HighCount:     0,
					MediumCount:   0,
					LowCount:      0,
					NoneCount:     0,
					UnknownCount:  0,
				},
				Vulnerabilities: []starboard.VulnerabilityItem{},
			},
		},
		{
			name: "Should convert vulnerability report in JSON format when scanning an image with digest in a private registry",
			input: `2020-06-21T23:10:15.162+0200	WARN	OS is not detected and vulnerabilities in OS packages are not detected.
null`,
			imageRef:      "core.harbor.domain/test/alpine@sha256:185518070891758909c9f839cf4ca393ee977ac378609f700f60a771a2dfe321",
			expectedError: nil,
			expectedReport: starboard.VulnerabilityReport{
				Scanner: starboard.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "0.9.1",
				},
				Artifact: starboard.Artifact{
					Repository: "test/alpine",
					Digest:     "sha256:185518070891758909c9f839cf4ca393ee977ac378609f700f60a771a2dfe321",
				},
				Registry: starboard.Registry{
					URL: "core.harbor.domain",
				},
				Vulnerabilities: []starboard.VulnerabilityItem{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := NewConverter().Convert(tc.imageRef, strings.NewReader(tc.input))
			switch {
			case tc.expectedError == nil:
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReport, report)
			default:
				assert.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}

}
