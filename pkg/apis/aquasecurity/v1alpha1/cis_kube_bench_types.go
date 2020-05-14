package v1alpha1

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	extv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CISKubeBenchReportCRName    = "ciskubebenchreports.aquasecurity.github.io"
	CISKubeBenchReportCRVersion = "v1alpha1"
	CISKubeBenchReportKind      = "CISKubeBenchReport"
	CISKubeBenchReportKindList  = "CISKubeBenchReportList"
)

var (
	CISKubeBenchReportCRD = extv1beta1.CustomResourceDefinition{
		ObjectMeta: meta.ObjectMeta{
			Name: CISKubeBenchReportCRName,
		},
		Spec: extv1beta1.CustomResourceDefinitionSpec{
			Group: aquasecurity.GroupName,
			Versions: []extv1beta1.CustomResourceDefinitionVersion{
				{
					Name:    CISKubeBenchReportCRVersion,
					Served:  true,
					Storage: true,
				},
			},
			Scope: extv1beta1.ClusterScoped,
			Names: extv1beta1.CustomResourceDefinitionNames{
				Singular:   "ciskubebenchreport",
				Plural:     "ciskubebenchreports",
				Kind:       CISKubeBenchReportKind,
				ListKind:   CISKubeBenchReportKindList,
				Categories: []string{"all"},
				ShortNames: []string{"kubebench"},
			},
		},
	}
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CISKubeBenchReport is a specification for the CISKubeBenchReport resource.
type CISKubeBenchReport struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata,omitempty"`

	Report CISKubeBenchOutput `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CISKubeBenchReportList is a list of CISKubeBenchReport resources.
type CISKubeBenchReportList struct {
	meta.TypeMeta `json:",inline"`
	meta.ListMeta `json:"metadata"`

	Items []CISKubeBenchReport `json:"items"`
}

type CISKubeBenchOutput struct {
	GeneratedAt meta.Time             `json:"generatedAt"`
	Scanner     Scanner               `json:"scanner"`
	Sections    []CISKubeBenchSection `json:"sections"`
}

type CISKubeBenchSection struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Text      string `json:"text"`
	NodeType  string `json:"node_type"`
	TotalPass int    `json:"total_pass"`
	TotalFail int    `json:"total_fail"`
	TotalWarn int    `json:"total_warn"`
	TotalInfo int    `json:"total_info"`

	Tests []CISKubeBenchTests `json:"tests"`
}

type CISKubeBenchTests struct {
	Section string `json:"section"`
	Pass    int    `json:"pass"`
	Fail    int    `json:"fail"`
	Warn    int    `json:"warn"`
	Info    int    `json:"info"`
	Desc    string `json:"desc"`

	Results []CISKubeBenchResult `json:"results"`
}

type CISKubeBenchResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Remediation string `json:"remediation"`
	Status      string `json:"status"`
	Scored      bool   `json:"scored"`
}
