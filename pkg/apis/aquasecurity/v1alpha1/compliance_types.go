package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ClusterComplianceSummary struct {
	PassCount int `json:"passCount"`
	FailCount int `json:"failCount"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterComplianceReport is a specification for the ClusterComplianceReport resource.
type ClusterComplianceReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ReportSpec   `json:"spec,omitempty"`
	Status            ReportStatus `json:"status,omitempty"`
}

//ReportSpec represent the compliance specification
type ReportSpec struct {
	Kind        string    `json:"specKind"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Cron        string    `json:"cron"`
	Version     string    `json:"version"`
	Controls    []Control `json:"controls"`
}

//Control represent the cps controls data and mapping checks
type Control struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,,omitempty"`
	Resources   []string `json:"resources"`
	Mapping     Mapping  `json:"mapping"`
}

//SpecCheck represent the tool who perform the control check
type SpecCheck struct {
	ID string `json:"id"`
}

//Mapping represent the tool who perform the control check
type Mapping struct {
	Tool   string      `json:"tool"`
	Checks []SpecCheck `json:"checks"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterComplianceReportList is a list of compliance resources.
type ClusterComplianceReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterComplianceReport `json:"items"`
}

type ReportStatus struct {
	UpdateTimestamp metav1.Time              `json:"updateTimestamp"`
	Summary         ClusterComplianceSummary `json:"summary"`
	ControlChecks   []ControlCheck           `json:"control_check"`
}

// ControlCheck provides the result of conducting a single audit step.
type ControlCheck struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	PassTotal   int    `json:"passTotal"`
	FailTotal   int    `json:"failTotal"`
	Severity    string `json:"severity"`
}