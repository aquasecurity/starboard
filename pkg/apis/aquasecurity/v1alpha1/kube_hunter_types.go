package v1alpha1

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	extv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	KubeHunterReportCRName    = "kubehunterreports.aquasecurity.github.io"
	KubeHunterReportCRVersion = "v1alpha1"
	KubeHunterReportKind      = "KubeHunterReport"
	KubeHunterReportListKind  = "KubeHunterReportList"
)

var (
	KubeHunterReportCRD = extv1beta1.CustomResourceDefinition{
		ObjectMeta: meta.ObjectMeta{
			Name: KubeHunterReportCRName,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
		},
		Spec: extv1beta1.CustomResourceDefinitionSpec{
			Group: aquasecurity.GroupName,
			Versions: []extv1beta1.CustomResourceDefinitionVersion{
				{
					Name:    KubeHunterReportCRVersion,
					Served:  true,
					Storage: true,
				},
			},
			Scope: extv1beta1.ClusterScoped,
			Names: extv1beta1.CustomResourceDefinitionNames{
				Singular:   "kubehunterreport",
				Plural:     "kubehunterreports",
				Kind:       KubeHunterReportKind,
				ListKind:   KubeHunterReportListKind,
				Categories: []string{"all"},
				ShortNames: []string{"kubehunter"},
			},
			AdditionalPrinterColumns: []extv1beta1.CustomResourceColumnDefinition{
				{
					JSONPath: ".report.scanner.name",
					Type:     "string",
					Name:     "Scanner",
				},
				{
					JSONPath: ".metadata.creationTimestamp",
					Type:     "date",
					Name:     "Age",
				},
				{
					JSONPath: ".report.summary.highCount",
					Type:     "integer",
					Name:     "High",
					Priority: 1,
				},
				{
					JSONPath: ".report.summary.mediumCount",
					Type:     "integer",
					Name:     "Medium",
					Priority: 1,
				},
				{
					JSONPath: ".report.summary.lowCount",
					Type:     "integer",
					Name:     "Low",
					Priority: 1,
				},
			},
		},
	}
)

const (
	KubeHunterSeverityHigh    Severity = "high"
	KubeHunterSeverityMedium  Severity = "medium"
	KubeHunterSeverityLow     Severity = "low"
	KubeHunterSeverityUnknown Severity = "unknown"
)

type KubeHunterSummary struct {
	HighCount    int `json:"highCount"`
	MediumCount  int `json:"mediumCount"`
	LowCount     int `json:"lowCount"`
	UnknownCount int `json:"unknownCount"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeHunterReport is a specification for the KubeHunterReport resource.
type KubeHunterReport struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata,omitempty"`

	Report KubeHunterOutput `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeHunterReportList is a list of KubeHunterReport resources.
type KubeHunterReportList struct {
	meta.TypeMeta `json:",inline"`
	meta.ListMeta `json:"metadata"`

	Items []KubeHunterReport `json:"items"`
}

type KubeHunterOutput struct {
	Scanner         Scanner                   `json:"scanner"`
	Summary         KubeHunterSummary         `json:"summary"`
	Vulnerabilities []KubeHunterVulnerability `json:"vulnerabilities"`
}

type KubeHunterVulnerability struct {
	Location      string   `json:"location"`      // e.g. "Local to Pod(kube-hunter-sj7zj)"
	ID            string   `json:"vid"`           // e.g. "KHV050"
	Category      string   `json:"category"`      // e.g. "Access Risk"
	Severity      Severity `json:"severity"`      // e.g. "low"
	Vulnerability string   `json:"vulnerability"` // e.g. "Read access to pod's service account token"
	Description   string   `json:"description"`   // e.g. "Accessing the pod service account token gives an attacker the option to use the server API"
	Evidence      string   `json:"evidence"`      // e.g. "eyJhbGciOiJSUzI1NiIMXA1..."
	Hunter        string   `json:"hunter"`        // e.g. "Access Secrets"
}
