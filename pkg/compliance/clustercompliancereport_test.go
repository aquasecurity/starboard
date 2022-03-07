package compliance

import (
	"context"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/google/go-cmp/cmp"
	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"io/ioutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sort"
)

func loadResource(filePath string, resource interface{}) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(data, &resource)
	if err != nil {
		return nil
	}
	return err
}

var _ = ginkgo.Describe("cluster compliance report", func() {
	config := etc.Config{
		Namespace: "starboard-operator",
	}

	ginkgo.Context("reconcile compliance spec report", func() {
		ginkgo.It("check compliance reconcile with cis-benchmark and config-audit reports", func() {
			var cisBenchList v1alpha1.CISKubeBenchReportList
			logger := log.Log.WithName("operator")
			err := loadResource("./testdata/fixture/cisBenchmarkReportList.json", &cisBenchList)
			Expect(err).ToNot(HaveOccurred())
			var confAuditList v1alpha1.ConfigAuditReportList
			err = loadResource("./testdata/fixture/configAuditReportList.json", &confAuditList)
			Expect(err).ToNot(HaveOccurred())
			var clusterComplianceSpec v1alpha1.ClusterComplianceReport
			err = loadResource("./testdata/fixture/clusterComplianceSpec.json", &clusterComplianceSpec)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewClientBuilder().WithScheme(starboard.NewScheme()).WithLists(
				&cisBenchList,
				&confAuditList,
			).WithObjects(
				&clusterComplianceSpec,
			).Build()
			// generate report
			instance := ClusterComplianceReportReconciler{Logger: logger, Config: config, Client: client, Mgr: NewMgr(client, logger)}
			_, err = instance.generateComplianceReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"})
			Expect(err).ToNot(HaveOccurred())

			// validate cluster details report
			var clusterComplianceDetialReport v1alpha1.ClusterComplianceDetailReport
			err = loadResource("./testdata/fixture/clusterComplianceDetailReport.json", &clusterComplianceDetialReport)
			complianceDetailReport, err := getDetailReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa-details"}, client)
			Expect(err).ToNot(HaveOccurred())
			sort.Sort(controlDetailSort(complianceDetailReport.Report.ControlChecks))
			sort.Sort(controlDetailSort(clusterComplianceDetialReport.Report.ControlChecks))
			for i := 0; i < len(complianceDetailReport.Report.ControlChecks); i++ {
				sort.Sort(controlObjectTypeSort(complianceDetailReport.Report.ControlChecks[i].ToolCheckResult))
				sort.Sort(controlObjectTypeSort(clusterComplianceDetialReport.Report.ControlChecks[i].ToolCheckResult))
			}
			Expect(cmp.Equal(complianceDetailReport.Report, clusterComplianceDetialReport.Report, ignoreTimeStamp())).To(BeTrue())

			// validate cluster compliance report
			var clusterComplianceReport v1alpha1.ClusterComplianceReport
			err = loadResource("./testdata/fixture/clusterComplianceReport.json", &clusterComplianceReport)
			complianceReport, err := getReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"}, client)
			Expect(err).ToNot(HaveOccurred())
			sort.Sort(controlSort(complianceReport.Status.ControlChecks))
			sort.Sort(controlSort(clusterComplianceReport.Status.ControlChecks))
			Expect(cmp.Equal(complianceReport.Status, clusterComplianceReport.Status, ignoreTimeStamp())).To(BeTrue())

			// validate reconcile requeue
			res, err := instance.generateComplianceReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"})
			Expect(err).ToNot(HaveOccurred())
			Expect(res.RequeueAfter > 0).To(BeTrue())
		})

		ginkgo.It("check compliance reconcile where cis-benchmark and config-audit reports are not present", func() {
			logger := log.Log.WithName("operator")
			var clusterComplianceSpec v1alpha1.ClusterComplianceReport
			err := loadResource("./testdata/fixture/clusterComplianceSpec.json", &clusterComplianceSpec)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewClientBuilder().WithScheme(starboard.NewScheme()).WithObjects(
				&clusterComplianceSpec,
			).Build()
			// generate report
			instance := ClusterComplianceReportReconciler{Logger: logger, Config: config, Client: client, Mgr: NewMgr(client, logger)}
			_, err = instance.generateComplianceReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"})
			Expect(err).ToNot(HaveOccurred())

			// validate cluster details report
			complianceDetailReport, err := getDetailReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa-details"}, client)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(complianceDetailReport.Report.ControlChecks) == 0).To(BeTrue())

			// validate cluster compliance report
			complianceReport, err := getReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"}, client)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(complianceReport.Status.ControlChecks) == 0).To(BeTrue())

			// validate reconcile requeue
			res, err := instance.generateComplianceReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"})
			Expect(err).ToNot(HaveOccurred())
			Expect(res.RequeueAfter > 0).To(BeTrue())
		})
	})
})

func ignoreTimeStamp() cmp.Options {
	alwaysEqual := cmp.Comparer(func(_, _ interface{}) bool { return true })
	opts := cmp.Options{
		cmp.FilterValues(func(t1, t2 metav1.Time) bool {
			return true
		}, alwaysEqual),
	}
	return opts
}

type controlSort []v1alpha1.ControlCheck

func (a controlSort) Len() int           { return len(a) }
func (a controlSort) Less(i, j int) bool { return a[i].ID < a[j].ID }
func (a controlSort) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type controlDetailSort []v1alpha1.ControlCheckDetails

func (a controlDetailSort) Len() int           { return len(a) }
func (a controlDetailSort) Less(i, j int) bool { return a[i].ID < a[j].ID }
func (a controlDetailSort) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type controlObjectTypeSort []v1alpha1.ToolCheckResult

func (a controlObjectTypeSort) Len() int           { return len(a) }
func (a controlObjectTypeSort) Less(i, j int) bool { return a[i].ObjectType < a[j].ObjectType }
func (a controlObjectTypeSort) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func getReport(ctx context.Context, namespaceName types.NamespacedName, client client.Client) (*v1alpha1.ClusterComplianceReport, error) {
	var report v1alpha1.ClusterComplianceReport
	err := client.Get(ctx, namespaceName, &report)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

func getDetailReport(ctx context.Context, namespaceName types.NamespacedName, client client.Client) (*v1alpha1.ClusterComplianceDetailReport, error) {
	var report v1alpha1.ClusterComplianceDetailReport
	err := client.Get(ctx, namespaceName, &report)
	if err != nil {
		return nil, err
	}
	return &report, nil
}
