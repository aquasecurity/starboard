package v1alpha1

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity"
	extv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ConfigAuditReportCRName    = "configauditreports.aquasecurity.github.io"
	ConfigAuditReportCRVersion = "v1alpha1"
	ConfigAuditReportKind      = "ConfigAuditReport"
	ConfigAuditReportListKind  = "ConfigAuditReportList"
)

var (
	ConfigAuditReportCRD = extv1beta1.CustomResourceDefinition{
		ObjectMeta: meta.ObjectMeta{
			Name: ConfigAuditReportCRName,
		},
		Spec: extv1beta1.CustomResourceDefinitionSpec{
			Group: aquasecurity.GroupName,
			Versions: []extv1beta1.CustomResourceDefinitionVersion{
				{
					Name:    ConfigAuditReportCRVersion,
					Served:  true,
					Storage: true,
				},
			},
			Scope: extv1beta1.NamespaceScoped,
			Names: extv1beta1.CustomResourceDefinitionNames{
				Singular:   "configauditreport",
				Plural:     "configauditreports",
				Kind:       ConfigAuditReportKind,
				ListKind:   ConfigAuditReportListKind,
				Categories: []string{"all"},
				ShortNames: []string{"configaudit"},
			},
		},
	}
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConfigAuditReport is a specification for the ConfigAuditReport resource.
type ConfigAuditReport struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata,omitempty"`

	Report ConfigAudit `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConfigAuditReportList is a list of AuditConfig resources.
type ConfigAuditReportList struct {
	meta.TypeMeta `json:",inline"`
	meta.ListMeta `json:"metadata"`

	Items []ConfigAuditReport `json:"items"`
}

// TODO We can make this type even more generic and applicable not only to Pods or Controllers
// TODO by defining scope type (e.g. Pod, Container, Node) and the name of the scope (e.g. my-pod, my-container,
// TODO my-node)
type ConfigAudit struct {
	Scanner         Scanner                      `json:"scanner"`
	Resource        KubernetesNamespacedResource `json:"resource"`
	PodChecks       []Check                      `json:"podChecks"`
	ContainerChecks map[string][]Check           `json:"containerChecks"`
}

type Check struct {
	ID       string `json:"checkID"`
	Message  string `json:"message"`
	Success  bool   `json:"success"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}
