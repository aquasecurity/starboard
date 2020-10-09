package trivy_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/trivy"

	starboardv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
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

	sampleReport = starboardv1alpha1.VulnerabilityScanResult{
		Scanner: starboardv1alpha1.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: "0.9.1",
		},
		Registry: starboardv1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: starboardv1alpha1.Artifact{
			Repository: "library/alpine",
			Tag:        "3.10.2",
		},
		Summary: starboardv1alpha1.VulnerabilitySummary{
			CriticalCount: 0,
			MediumCount:   1,
			LowCount:      1,
			NoneCount:     0,
			UnknownCount:  0,
		},
		Vulnerabilities: []starboardv1alpha1.Vulnerability{
			{
				VulnerabilityID:  "CVE-2019-1549",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         starboardv1alpha1.SeverityMedium,
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
				Severity:         starboardv1alpha1.SeverityLow,
				Title:            "openssl: side-channel weak encryption vulnerability",
				Links: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
				},
			},
		},
	}
)

func TestConverter_Convert(t *testing.T) {
	config := starboard.ConfigData{
		"trivy.imageRef": "aquasec/trivy:0.9.1",
	}

	testCases := []struct {
		name           string
		imageRef       string
		input          string
		expectedError  error
		expectedReport starboardv1alpha1.VulnerabilityScanResult
	}{
		{
			name:     "Should convert vulnerability report in JSON format when input is noisy",
			imageRef: "alpine:3.10.2",
			input: fmt.Sprintf("2020-06-17T23:37:45.320+0200	[34mINFO[0m	Detecting Alpine vulnerabilities...\n%s", sampleReportAsString),
			expectedError:  nil,
			expectedReport: sampleReport,
		},
		{
			name:           "Should convert vulnerability report in JSON format when input is quiet",
			imageRef:       "alpine:3.10.2",
			input:          sampleReportAsString,
			expectedError:  nil,
			expectedReport: sampleReport,
		},
		{
			name:     "Should convert vulnerability report in JSON format when OS is not detected",
			imageRef: "core.harbor.domain/library/nginx@sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
			input: `2020-06-21T23:10:15.162+0200	WARN	OS is not detected and vulnerabilities in OS packages are not detected.
null`,
			expectedError: nil,
			expectedReport: starboardv1alpha1.VulnerabilityScanResult{
				Scanner: starboardv1alpha1.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "0.9.1",
				},
				Registry: starboardv1alpha1.Registry{
					Server: "core.harbor.domain",
				},
				Artifact: starboardv1alpha1.Artifact{
					Repository: "library/nginx",
					Digest:     "sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
				},
				Summary: starboardv1alpha1.VulnerabilitySummary{
					CriticalCount: 0,
					HighCount:     0,
					MediumCount:   0,
					LowCount:      0,
					NoneCount:     0,
					UnknownCount:  0,
				},
				Vulnerabilities: []starboardv1alpha1.Vulnerability{},
			},
		},
		{
			name:          "Should return error when image reference cannot be parsed",
			imageRef:      ":",
			input:         "null",
			expectedError: errors.New("could not parse reference: :"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := trivy.NewConverter().Convert(config, tc.imageRef, strings.NewReader(tc.input))
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
