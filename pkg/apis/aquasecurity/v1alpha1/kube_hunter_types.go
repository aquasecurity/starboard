package v1alpha1

import (
	"strconv"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
)

const (
	KubeHunterReportCRName    = "kubehunterreports.aquasecurity.github.io"
	KubeHunterReportCRVersion = "v1alpha1"
	KubeHunterReportKind      = "KubeHunterReport"
	KubeHunterReportListKind  = "KubeHunterReportList"
)

var (
	// TODO Once we migrate to Go 1.16 we can use the embed package to load the CRD from ./deploy/crd/kubehunterreports.crd.yaml
	KubeHunterReportCRD = apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeHunterReportCRName,
			Labels: labels.Set{
				"app.kubernetes.io/managed-by": "starboard",
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: aquasecurity.GroupName,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    KubeHunterReportCRVersion,
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
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
							Required: []string{
								"apiVersion",
								"kind",
								"metadata",
								"report",
							},
							Properties: map[string]apiextensionsv1.JSONSchemaProps{
								"apiVersion": {Type: "string"},
								"kind":       {Type: "string"},
								"metadata":   {Type: "object"},
								"report": {
									Type: "object",
									Required: []string{
										"scanner",
										"vulnerabilities",
									},
									Properties: map[string]apiextensionsv1.JSONSchemaProps{
										"scanner": {
											Type: "object",
											Required: []string{
												"name",
												"vendor",
												"version",
											},
											Properties: map[string]apiextensionsv1.JSONSchemaProps{
												"name":    {Type: "string"},
												"vendor":  {Type: "string"},
												"version": {Type: "string"},
											},
										},
										"summary": {
											Type: "object",
											Required: []string{
												"highCount",
												"mediumCount",
												"lowCount",
												"unknownCount",
											},
											Properties: map[string]apiextensionsv1.JSONSchemaProps{
												"highCount":    {Type: "integer", Minimum: pointer.Float64Ptr(0)},
												"mediumCount":  {Type: "integer", Minimum: pointer.Float64Ptr(0)},
												"lowCount":     {Type: "integer", Minimum: pointer.Float64Ptr(0)},
												"unknownCount": {Type: "integer", Minimum: pointer.Float64Ptr(0)},
											},
										},
										"updateTimestamp": {
											Type:   "string",
											Format: "date-time",
										},
										"vulnerabilities": {
											Type: "array",
											Items: &apiextensionsv1.JSONSchemaPropsOrArray{
												Schema: &apiextensionsv1.JSONSchemaProps{
													Type: "object",
													Required: []string{
														"category",
														"severity",
														"vulnerability",
														"description",
														"evidence",
													},
													Properties: map[string]apiextensionsv1.JSONSchemaProps{
														"id":       {Type: "string"},
														"category": {Type: "string"},
														"severity": {
															Type: "string",
															Enum: []apiextensionsv1.JSON{
																{Raw: []byte(strconv.Quote(string(KubeHunterSeverityHigh)))},
																{Raw: []byte(strconv.Quote(string(KubeHunterSeverityMedium)))},
																{Raw: []byte(strconv.Quote(string(KubeHunterSeverityLow)))},
																{Raw: []byte(strconv.Quote(string(KubeHunterSeverityUnknown)))},
															},
														},
														"vulnerability": {Type: "string"},
														"description":   {Type: "string"},
														"evidence":      {Type: "string"},
														"avd_reference":  {Type: "string"},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Scope: apiextensionsv1.ClusterScoped,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Singular:   "kubehunterreport",
				Plural:     "kubehunterreports",
				Kind:       KubeHunterReportKind,
				ListKind:   KubeHunterReportListKind,
				Categories: []string{"all"},
				ShortNames: []string{"kubehunter"},
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
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report KubeHunterOutput `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeHunterReportList is a list of KubeHunterReport resources.
type KubeHunterReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []KubeHunterReport `json:"items"`
}

type KubeHunterOutput struct {
	UpdateTimestamp metav1.Time               `json:"updateTimestamp"`
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
	AvdReference  string   `json:"avd_reference"` // e.g. "Aqua vulnerability database reference"
}
