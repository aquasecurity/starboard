package trivy

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type ScanReport struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string            `json:"VulnerabilityID"`
	PkgName          string            `json:"PkgName"`
	InstalledVersion string            `json:"InstalledVersion"`
	FixedVersion     string            `json:"FixedVersion"`
	Title            string            `json:"Title"`
	Description      string            `json:"Description"`
	Severity         v1alpha1.Severity `json:"Severity"`
	Layer            Layer             `json:"Layer"`
	PrimaryURL       string            `json:"PrimaryURL"`
	References       []string          `json:"References"`
}

type Layer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}
