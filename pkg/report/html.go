package report

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/report/templates"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type workloadReporter struct {
	clock                      ext.Clock
	vulnerabilityReportsReader vulnerabilityreport.ReadWriter
	configAuditReportsReader   configauditreport.ReadWriter
}

func NewWorkloadReporter(clock ext.Clock, kubeClientset kubernetes.Interface, client client.Client) WorkloadReporter {
	return &workloadReporter{
		clock:                      clock,
		vulnerabilityReportsReader: vulnerabilityreport.NewReadWriter(client, kubeClientset),
		configAuditReportsReader:   configauditreport.NewReadWriter(client, kubeClientset),
	}
}

func (h *workloadReporter) RetrieveData(workload kube.Object) (templates.WorkloadReport, error) {
	ctx := context.Background()
	configAuditReport, err := h.configAuditReportsReader.FindByOwnerInHierarchy(ctx, workload)
	if err != nil {
		return templates.WorkloadReport{}, err
	}
	vulnerabilityReports, err := h.vulnerabilityReportsReader.FindByOwnerInHierarchy(ctx, workload)
	if err != nil {
		return templates.WorkloadReport{}, err
	}

	vulnsReports := map[string]v1alpha1.VulnerabilityScanResult{}
	for _, vulnerabilityReport := range vulnerabilityReports {
		containerName, ok := vulnerabilityReport.Labels[kube.LabelContainerName]
		if !ok {
			continue
		}

		sort.Stable(vulnerabilityreport.BySeverity{Vulnerabilities: vulnerabilityReport.Report.Vulnerabilities})

		vulnsReports[containerName] = vulnerabilityReport.Report
	}
	if configAuditReport == nil && len(vulnsReports) == 0 {
		return templates.WorkloadReport{}, fmt.Errorf("no configaudits or vulnerabilities found for workload %s/%s/%s",
			workload.Namespace, workload.Kind, workload.Name)
	}
	return templates.WorkloadReport{
		Workload:          workload,
		GeneratedAt:       h.clock.Now(),
		VulnsReports:      vulnsReports,
		ConfigAuditReport: configAuditReport,
	}, nil
}

func (h *workloadReporter) Generate(workload kube.Object, writer io.Writer) error {
	data, err := h.RetrieveData(workload)
	if err != nil {
		return err
	}

	templates.WritePageTemplate(writer, &data)
	return nil
}

type namespaceReport struct {
	clock  ext.Clock
	client client.Client
}

func NewNamespaceReporter(clock ext.Clock, client client.Client) NamespaceReporter {
	return &namespaceReport{
		clock:  clock,
		client: client,
	}
}

func (r *namespaceReport) RetrieveData(namespace kube.Object) (templates.NamespaceReport, error) {
	var vulnerabilityReportList v1alpha1.VulnerabilityReportList
	err := r.client.List(context.Background(), &vulnerabilityReportList, client.InNamespace(namespace.Name))
	if err != nil {
		return templates.NamespaceReport{}, err
	}

	return templates.NamespaceReport{
		Namespace:            namespace,
		GeneratedAt:          r.clock.Now(),
		Top5VulnerableImages: r.topNImagesBySeverityCount(vulnerabilityReportList.Items, 5),
	}, nil
}

func (r *namespaceReport) topNImagesBySeverityCount(reports []v1alpha1.VulnerabilityReport, N int) []v1alpha1.VulnerabilityReport {
	b := append(reports[:0:0], reports...)

	vulnerabilityreport.OrderedBy(vulnerabilityreport.SummaryCount...).
		SortDesc(b)

	return b[:ext.MinInt(N, len(b))]
}

func (r *namespaceReport) Generate(namespace kube.Object, out io.Writer) error {
	data, err := r.RetrieveData(namespace)
	if err != nil {
		return err
	}
	templates.WritePageTemplate(out, &data)
	return nil
}

type nodeReport struct {
	clock                      ext.Clock
	client                     client.Client
	vulnerabilityReportsReader vulnerabilityreport.ReadWriter
}

// NewNodeReporter generate the html reporter
func NewNodeReporter(clock ext.Clock, client client.Client) NodeReporter {
	return &nodeReport{
		clock:  clock,
		client: client,
	}
}

func (r *nodeReport) Generate(node kube.Object, out io.Writer) error {
	data, err := r.RetrieveData(node)
	if err != nil {
		return err
	}
	templates.WritePageTemplate(out, &data)
	return nil
}

func (r *nodeReport) RetrieveData(node kube.Object) (templates.NodeReport, error) {
	var cisKubeBenchReportList v1alpha1.CISKubeBenchReportList
	err := r.client.List(context.Background(), &cisKubeBenchReportList, client.InNamespace(node.Name))
	if err != nil {
		return templates.NodeReport{}, err
	}

	return templates.NodeReport{
		GeneratedAt: r.clock.Now(),
	}, nil
}

func (r *nodeReport) vulnerabilities(reports []v1alpha1.CISKubeBenchReport, N int) []v1alpha1.CISKubeBenchReport {
	b := append(reports[:0:0], reports...)

	return b[:ext.MinInt(N, len(b))]
}
