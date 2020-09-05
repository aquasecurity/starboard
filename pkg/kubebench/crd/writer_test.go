package crd_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/starboard/pkg/cmd"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	starboardClientset "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	starboardClientsetFake "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned/fake"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kubebench/crd"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestReadWriter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ReadWriter Suite")
}

var _ = Describe("ReadWriter", func() {

	var (
		workerNodeName = "worker-node"
		workerNode     = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: workerNodeName,
			},
		}
		workerNodeReport = v1alpha1.CISKubeBenchOutput{
			Scanner: v1alpha1.Scanner{
				Name: "worker-node-report",
			},
		}
	)

	var (
		objects   []runtime.Object
		clientset starboardClientset.Interface
		rw        *crd.ReadWriter
	)

	BeforeEach(func() {
		objects = []runtime.Object{}
		clientset = starboardClientsetFake.NewSimpleClientset(objects...)
		rw = crd.NewReadWriter(cmd.GetScheme(), clientset)
	})

	Describe("Writing report", func() {

		Context("when report does not exist", func() {

			It("should create a report", func() {
				err := rw.Write(context.TODO(), workerNodeReport, workerNode)
				Expect(err).ToNot(HaveOccurred())

				report, err := clientset.AquasecurityV1alpha1().CISKubeBenchReports().
					Get(context.TODO(), workerNodeName, metav1.GetOptions{})

				Expect(err).ToNot(HaveOccurred())
				Expect(report.Labels).To(MatchAllKeys(Keys{
					kube.LabelResourceKind:  Equal(string(kube.KindNode)),
					kube.LabelResourceName:  Equal(workerNodeName),
					kube.LabelHistoryLatest: Equal("true"),
				}))
			})

		})

		Context("when report already exists", func() {

			BeforeEach(func() {
				err := rw.Write(context.TODO(), workerNodeReport, workerNode)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should update a report", func() {
				err := rw.Write(context.TODO(), workerNodeReport, workerNode)
				Expect(err).ToNot(HaveOccurred())

				report, err := clientset.AquasecurityV1alpha1().CISKubeBenchReports().
					Get(context.TODO(), workerNodeName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred())

				Expect(report.Labels).To(MatchAllKeys(Keys{
					kube.LabelResourceKind:  Equal(string(kube.KindNode)),
					kube.LabelResourceName:  Equal(workerNodeName),
					kube.LabelHistoryLatest: Equal("true"),
				}))

				reportList, err := clientset.AquasecurityV1alpha1().CISKubeBenchReports().
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind: string(kube.KindNode),
							kube.LabelResourceName: workerNodeName,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(HaveLen(1))
			})
		})

	})

	Describe("Reading report", func() {

		Context("when report does not exist", func() {

			It("should return error not found", func() {
				_, err := rw.Read(context.TODO(), kube.Object{
					Kind: kube.KindNode,
					Name: workerNodeName,
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("ciskubebenchreports.aquasecurity.github.io \"worker-node\" not found"))
			})

		})

		Context("when report exists", func() {

			BeforeEach(func() {
				err := rw.Write(context.TODO(), workerNodeReport, workerNode)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return report", func() {
				report, err := rw.Read(context.TODO(), kube.Object{
					Kind: kube.KindNode,
					Name: workerNodeName,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(report).To(Equal(workerNodeReport))
			})

		})
	})

})
