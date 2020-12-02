package trivy_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/starboard/pkg/trivy"

	"github.com/aquasecurity/starboard/pkg/starboard"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	sampleReportAsString = `[{
		"Target": "alpine:3.10.2 (alpine 3.10.2)",
		"Type": "alpine",
		"Vulnerabilities": [
			{
				"VulnerabilityID": "CVE-2019-1549",
				"PkgName": "openssl",
				"InstalledVersion": "1.1.1c-r0",
				"FixedVersion": "1.1.1d-r0",
				"Title": "openssl: information disclosure in fork()",
				"Description": "Usually this long long description of CVE-2019-1549",
				"Severity": "MEDIUM",
				"PrimaryURL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549",
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
				"PrimaryURL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
				"References": [
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547"
				]
			}
		]
	}]`

	sampleReport = v1alpha1.VulnerabilityScanResult{
		Scanner: v1alpha1.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: "0.9.1",
		},
		Registry: v1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: v1alpha1.Artifact{
			Repository: "library/alpine",
			Tag:        "3.10.2",
		},
		Summary: v1alpha1.VulnerabilitySummary{
			CriticalCount: 0,
			MediumCount:   1,
			LowCount:      1,
			NoneCount:     0,
			UnknownCount:  0,
		},
		Vulnerabilities: []v1alpha1.Vulnerability{
			{
				VulnerabilityID:  "CVE-2019-1549",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         v1alpha1.SeverityMedium,
				Title:            "openssl: information disclosure in fork()",
				PrimaryLink:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549",
				Links:            []string{},
			},
			{
				VulnerabilityID:  "CVE-2019-1547",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         v1alpha1.SeverityLow,
				Title:            "openssl: side-channel weak encryption vulnerability",
				PrimaryLink:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
				Links:            []string{},
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
		expectedReport v1alpha1.VulnerabilityScanResult
	}{
		{
			name:           "Should convert vulnerability report in JSON format when input is quiet",
			imageRef:       "alpine:3.10.2",
			input:          sampleReportAsString,
			expectedError:  nil,
			expectedReport: sampleReport,
		},
		{
			name:          "Should convert vulnerability report in JSON format when OS is not detected",
			imageRef:      "core.harbor.domain/library/nginx@sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
			input:         `null`,
			expectedError: nil,
			expectedReport: v1alpha1.VulnerabilityScanResult{
				Scanner: v1alpha1.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "0.9.1",
				},
				Registry: v1alpha1.Registry{
					Server: "core.harbor.domain",
				},
				Artifact: v1alpha1.Artifact{
					Repository: "library/nginx",
					Digest:     "sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
				},
				Summary: v1alpha1.VulnerabilitySummary{
					CriticalCount: 0,
					HighCount:     0,
					MediumCount:   0,
					LowCount:      0,
					NoneCount:     0,
					UnknownCount:  0,
				},
				Vulnerabilities: []v1alpha1.Vulnerability{},
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
			report, err := trivy.NewConverter(config).Convert(tc.imageRef, strings.NewReader(tc.input))
			fakeTime := metav1.NewTime(time.Now())
			report.UpdateTimestamp = fakeTime
			tc.expectedReport.UpdateTimestamp = fakeTime
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
