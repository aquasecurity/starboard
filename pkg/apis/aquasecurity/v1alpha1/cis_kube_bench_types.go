package v1alpha1

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
)

const (
	CISKubeBenchReportCRName    = "ciskubebenchreports.aquasecurity.github.io"
	CISKubeBenchReportCRVersion = "v1alpha1"
	CISKubeBenchReportKind      = "CISKubeBenchReport"
	CISKubeBenchReportListKind  = "CISKubeBenchReportList"
)

var (
	// TODO Once we migrate to Go 1.16 we can use the embed package to load the CRD from ./deploy/crd/ciskubebenchreports.crd.yaml
	CISKubeBenchReportCRD = apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: CISKubeBenchReportCRName,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: aquasecurity.GroupName,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    CISKubeBenchReportCRVersion,
					Served:  true,
					Storage: true,
					AdditionalPrinterColumns: []apiextensionsv1.CustomResourceColumnDefinition{
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
							JSONPath: ".report.summary.failCount",
							Type:     "integer",
							Name:     "Fail",
							Priority: 1,
						},
						{
							JSONPath: ".report.summary.warnCount",
							Type:     "integer",
							Name:     "Warn",
							Priority: 1,
						},
						{
							JSONPath: ".report.summary.infoCount",
							Type:     "integer",
							Name:     "Info",
							Priority: 1,
						},
						{
							JSONPath: ".report.summary.passCount",
							Type:     "integer",
							Name:     "Pass",
							Priority: 1,
						},
					},
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							XPreserveUnknownFields: pointer.BoolPtr(true),
							Type:                   "object",
						},
					},
				},
			},
			Scope: apiextensionsv1.ClusterScoped,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Singular:   "ciskubebenchreport",
				Plural:     "ciskubebenchreports",
				Kind:       CISKubeBenchReportKind,
				ListKind:   CISKubeBenchReportListKind,
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
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report CISKubeBenchOutput `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CISKubeBenchReportList is a list of CISKubeBenchReport resources.
type CISKubeBenchReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CISKubeBenchReport `json:"items"`
}

type CISKubeBenchOutput struct {
	UpdateTimestamp metav1.Time           `json:"updateTimestamp"`
	Scanner         Scanner               `json:"scanner"`
	Summary         CISKubeBenchSummary   `json:"summary"`
	Sections        []CISKubeBenchSection `json:"sections"`
}

type CISKubeBenchSummary struct {
	PassCount int `json:"passCount"`
	InfoCount int `json:"infoCount"`
	WarnCount int `json:"warnCount"`
	FailCount int `json:"failCount"`
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
