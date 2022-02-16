package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ClusterComplianceDetailSummary struct {
	PassCount int `json:"passCount"`
	FailCount int `json:"failCount"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterComplianceDetailReport is a specification for the ClusterComplianceDetailReport resource.
type ClusterComplianceDetailReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Report            ClusterComplianceDetailReportData `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterComplianceDetailReportList is a list of compliance resources.
type ClusterComplianceDetailReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterComplianceReport `json:"items"`
}

type ClusterComplianceDetailReportData struct {
	UpdateTimestamp metav1.Time                    `json:"updateTimestamp"`
	Type            Compliance                     `json:"type"`
	Summary         ClusterComplianceDetailSummary `json:"summary"`
	ControlChecks   []ControlCheckDetails          `json:"controlCheck"`
}

// ControlCheckDetails provides the result of conducting a single audit step.
type ControlCheckDetails struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	ToolCheckResult ToolCheckResult `json:"checkResults"`
}

type ResultDetails struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Status    string `json:"status"`
}

type ToolCheckResult struct {
	ObjectType  string          `json:"objectType"`
	ID          string          `json:"id"`
	Remediation string          `json:"remediation"`
	Details     []ResultDetails `json:"details"`
}
