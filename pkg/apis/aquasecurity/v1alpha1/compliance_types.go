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
	Report            ClusterComplianceReportData `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterComplianceReportList is a list of compliance resources.
type ClusterComplianceReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterComplianceReport `json:"items"`
}

type ClusterComplianceReportData struct {
	UpdateTimestamp metav1.Time              `json:"updateTimestamp"`
	Type            Compliance               `json:"type"`
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
