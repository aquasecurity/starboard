package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ClusterNsaReportCRName = "clusternsareports.aquasecurity.github.io"
)

const (
	NsaSeverityDanger  = "danger"
	NsaSeverityWarning = "warning"
)

type NsaSummary struct {
	PassCount    int `json:"passCount"`
	DangerCount  int `json:"dangerCount"`
	WarningCount int `json:"warningCount"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterNsaReport is a specification for the ClusterNsaReport resource.
type ClusterNsaReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report ClusterNsaReportData `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterNsaReportList is a list of ClusterNsaReportList resources.
type ClusterNsaReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterNsaReport `json:"items"`
}

type ClusterNsaReportData struct {
	UpdateTimestamp metav1.Time `json:"updateTimestamp"`
	Scanner         Scanner     `json:"scanner"`
	Summary         NsaSummary  `json:"summary"`

	// Checks provides results of conducting audit steps.
	Checks []NsaCheck `json:"checks"`
}

// NsaCheckScope has Type and Value fields to further identify a given Check.
// For example, we can use `Container` as Type and `nginx` as Value to indicate
// that a particular check is relevant to the nginx container. Alternatively,
// Type may be `JSONPath` and the Value would be JSONPath expression, e.g.
// `.spec.container[0].securityContext.allowPrivilegeEscalation`.
//
// Another use case for CheckScope is to inspect a ConfigMap with many keys and
// indicate a troublesome key. In this case the Type would be `ConfigMapKey`
// and the Value will hold the name of a key, e.g. `myawsprivatekey`.
type NsaCheckScope struct {

	// Type indicates type of this scope, e.g. Container, ConfigMapKey or JSONPath.
	Type string `json:"type"`

	// Value indicates value of this scope that depends on Type, e.g. container name, ConfigMap key or JSONPath expression
	Value string `json:"value"`
}

// NsaCheck provides the result of conducting a single audit step.
type NsaCheck struct {
	ID      string `json:"checkID"`
	Message string `json:"message"`

	// Remediation provides description or links to external resources to remediate failing check.
	// +optional
	Remediation string `json:"remediation,omitempty"`

	Success  bool   `json:"success"`
	Severity string `json:"severity"`
	Category string `json:"category"`

	// Scope indicates the section of config that was audited.
	// +optional
	Scope *CheckScope `json:"scope,omitempty"`
}
