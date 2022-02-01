package nsa

import (
	"context"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Writer interface {
	WriteInfra(ctx context.Context, report v1alpha1.CISKubeBenchReport) error
	WriteConfig(ctx context.Context, report v1alpha1.ClusterConfigAuditReport) error
}

type Reader interface {
	FindByOwner(ctx context.Context, node kube.ObjectRef) (interface{}, error)
}

type ReadWriter interface {
	Writer
	Reader
}

type rw struct {
	client client.Client
}

func (w *rw) WriteConfig(ctx context.Context, report v1alpha1.ClusterConfigAuditReport) error {
	var existing v1alpha1.ClusterNsaReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: report.Name,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = configAuditDataToNsaReportData(report.Report)
		return w.client.Update(ctx, copied)
	}
	if errors.IsNotFound(err) {
		new := v1alpha1.ClusterNsaReport{}
		new.Namespace = report.Namespace
		new.Name = report.Name
		new.CreationTimestamp = report.CreationTimestamp
		new.Annotations = report.Annotations
		new.Labels = report.Labels
		new.Report = configAuditDataToNsaReportData(report.Report)
		return w.client.Create(ctx, &new)
	}
	return nil
}

func NewReadWriter(client client.Client) ReadWriter {
	return &rw{
		client: client,
	}
}

func (w *rw) WriteInfra(ctx context.Context, report v1alpha1.CISKubeBenchReport) error {
	// TODO Try CreateOrUpdate method
	var existing v1alpha1.ClusterNsaReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: report.Name,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = cisReportDataToNsaReportData(report.Report)
		return w.client.Update(ctx, copied)
	}

	if errors.IsNotFound(err) {
		new := v1alpha1.ClusterNsaReport{}
		new.Namespace = report.Namespace
		new.Name = report.Name
		new.CreationTimestamp = report.CreationTimestamp
		new.Annotations = report.Annotations
		new.Labels = report.Labels
		new.Report = cisReportDataToNsaReportData(report.Report)
		return w.client.Create(ctx, &new)
	}

	return err
}

func (w *rw) FindByOwner(ctx context.Context, node kube.ObjectRef) (interface{}, error) {
	report := &v1alpha1.ClusterNsaReport{}
	err := w.client.Get(ctx, types.NamespacedName{
		Name: node.Name,
	}, report)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return report, nil
}

func cisReportDataToNsaReportData(reportData v1alpha1.CISKubeBenchReportData) v1alpha1.ClusterNsaReportData {
	crd := v1alpha1.ClusterNsaReportData{}
	crd.Checks = make([]v1alpha1.NsaCheck, 0)
	crd.Scanner = v1alpha1.Scanner{Name: "nsa-infra", Vendor: reportData.Scanner.Vendor, Version: reportData.Scanner.Version}
	crd.UpdateTimestamp = reportData.UpdateTimestamp
	crd.Summary.DangerCount = reportData.Summary.FailCount
	crd.Summary.WarningCount = reportData.Summary.WarnCount
	crd.Summary.PassCount = reportData.Summary.PassCount
	for _, section := range reportData.Sections {
		for _, test := range section.Tests {
			for _, result := range test.Results {
				var success bool
				switch result.Status {
				case "WARN":
					continue
				case "FAIl":
					success = false
				case "PASS":
					success = true
				}
				crd.Checks = append(crd.Checks, v1alpha1.NsaCheck{ID: result.TestNumber, Message: result.TestDesc, Remediation: result.Remediation, Success: success})
			}
		}
	}
	return crd
}

func configAuditDataToNsaReportData(reportData v1alpha1.ConfigAuditReportData) v1alpha1.ClusterNsaReportData {
	crd := v1alpha1.ClusterNsaReportData{}
	checks := make([]v1alpha1.NsaCheck, 0)
	crd.Scanner = v1alpha1.Scanner{Name: "nsa-config", Vendor: reportData.Scanner.Vendor, Version: reportData.Scanner.Version}
	crd.Summary.DangerCount = reportData.Summary.DangerCount
	crd.Summary.WarningCount = reportData.Summary.WarningCount
	crd.Summary.PassCount = reportData.Summary.PassCount
	for _, check := range reportData.Checks {
		checks = append(checks, v1alpha1.NsaCheck{ID: check.ID, Message: check.Message, Remediation: check.Remediation, Success: check.Success})
	}
	crd.Checks = checks
	return crd
}