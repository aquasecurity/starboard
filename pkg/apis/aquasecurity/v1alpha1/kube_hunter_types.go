package v1alpha1

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	extv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KubeHunterReportKind      = "KubeHunterReport"
	KubeHunterReportListKind  = "KubeHunterReportList"
	KubeHunterReportCRName    = "kubehunterreports.aquasecurity.github.com"
	KubeHunterReportCRVersion = "v1alpha1"
)

var (
	KubeHunterReportCRD = extv1beta1.CustomResourceDefinition{
		ObjectMeta: meta.ObjectMeta{
			Name: KubeHunterReportCRName,
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
			},
		},
	}
)

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
	GeneratedAt meta.Time `json:"generatedAt"`
	Scanner     Scanner   `json:"scanner"`

	Vulnerabilities []KubeHunterVulnerability `json:"vulnerabilities"`
}

type KubeHunterVulnerability struct {
	Location      string `json:"location"`      // e.g. "Local to Pod(kube-hunter-sj7zj)"
	ID            string `json:"vid"`           // e.g. "KHV050"
	Category      string `json:"category"`      // e.g. "Access Risk"
	Severity      string `json:"severity"`      // e.g. "low"
	Vulnerability string `json:"vulnerability"` // e.g. "Read access to pod's service account token"
	Description   string `json:"description"`   // e.g. "Accessing the pod service account token gives an attacker the option to use the server API"
	Evidence      string `json:"evidence"`      // e.g. "eyJhbGciOiJSUzI1NiIMXA1..."
	Hunter        string `json:"hunter"`        // e.g. "Access Secrets"
}
