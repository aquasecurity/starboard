package v1alpha1

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	extv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CISKubernetesBenchmarksCRName    = "ciskubernetesbenchmarks.aquasecurity.github.com"
	CISKubernetesBenchmarksCRVersion = "v1alpha1"
)

var (
	CISKubernetesBenchmarksCRD = extv1beta1.CustomResourceDefinition{
		ObjectMeta: meta.ObjectMeta{
			Name: CISKubernetesBenchmarksCRName,
		},
		Spec: extv1beta1.CustomResourceDefinitionSpec{
			Group: aquasecurity.GroupName,
			Versions: []extv1beta1.CustomResourceDefinitionVersion{
				{
					Name:    CISKubernetesBenchmarksCRVersion,
					Served:  true,
					Storage: true,
				},
			},
			Scope: extv1beta1.ClusterScoped,
			Names: extv1beta1.CustomResourceDefinitionNames{
				Singular:   "ciskubernetesbenchmark",
				Plural:     "ciskubernetesbenchmarks",
				Kind:       "CISKubernetesBenchmark",
				ListKind:   "CISKubernetesBenchmarkList",
				Categories: []string{"all"},
				ShortNames: []string{"ciskubebench"},
			},
		},
	}
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CISKubernetesBenchmark is a specification for the CISKubernetesBenchmark resource.
type CISKubernetesBenchmark struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata,omitempty"`

	Report CISKubernetesBenchmarkReport `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CISKubernetesBenchmarkList is a list of CISKubernetesBenchmark resources.
type CISKubernetesBenchmarkList struct {
	meta.TypeMeta `json:",inline"`
	meta.ListMeta `json:"metadata"`

	Items []CISKubernetesBenchmark `json:"items"`
}

type CISKubernetesBenchmarkReport struct {
	GeneratedAt meta.Time                       `json:"generatedAt"`
	Scanner     Scanner                         `json:"scanner"`
	Sections    []CISKubernetesBenchmarkSection `json:"sections"`
}

type CISKubernetesBenchmarkSection struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Text      string `json:"text"`
	NodeType  string `json:"node_type"`
	TotalPass int    `json:"total_pass"`
	TotalFail int    `json:"total_fail"`
	TotalWarn int    `json:"total_warn"`
	TotalInfo int    `json:"total_info"`

	Tests []CISKubernetesBenchmarkTests `json:"tests"`
}

type CISKubernetesBenchmarkTests struct {
	Section string `json:"section"`
	Pass    int    `json:"pass"`
	Fail    int    `json:"fail"`
	Warn    int    `json:"warn"`
	Info    int    `json:"info"`
	Desc    string `json:"desc"`

	Results []CISKubernetesBenchmarkResult `json:"results"`
}

type CISKubernetesBenchmarkResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Remediation string `json:"remediation"`
	Status      string `json:"status"`
	Scored      bool   `json:"scored"`
}
