package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ConfigAuditReportCRName    = "configauditreports.aquasecurity.github.io"
	ConfigAuditReportCRVersion = "v1alpha1"
	ConfigAuditReportKind      = "ConfigAuditReport"
	ConfigAuditReportListKind  = "ConfigAuditReportList"
)

const (
	ConfigAuditSeverityDanger  = "danger"
	ConfigAuditSeverityWarning = "warning"
)

type ConfigAuditSummary struct {
	PassCount    int `json:"passCount"`
	DangerCount  int `json:"dangerCount"`
	WarningCount int `json:"warningCount"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConfigAuditReport is a specification for the ConfigAuditReport resource.
type ConfigAuditReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report ConfigAuditResult `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ConfigAuditReportList is a list of AuditConfig resources.
type ConfigAuditReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ConfigAuditReport `json:"items"`
}

type ConfigAuditResult struct {
	UpdateTimestamp metav1.Time        `json:"updateTimestamp"`
	Scanner         Scanner            `json:"scanner"`
	Summary         ConfigAuditSummary `json:"summary"`
	PodChecks       []Check            `json:"podChecks"`
	ContainerChecks map[string][]Check `json:"containerChecks"`
}

type Check struct {
	ID       string `json:"checkID"`
	Message  string `json:"message"`
	Success  bool   `json:"success"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}
