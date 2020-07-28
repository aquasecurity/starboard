package itest

import (
	"context"
	"os/exec"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	. "github.com/onsi/gomega/gbytes"

	"github.com/aquasecurity/starboard/pkg/kube"
	. "github.com/onsi/gomega/gstruct"

	. "github.com/onsi/gomega/gexec"
	apiextentions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	scanJobTimeout = 2 * time.Minute
)

var _ = Describe("Starboard CLI", func() {

	BeforeEach(func() {
		command := exec.Command(pathToStarboardCLI, []string{"init", "-v", "3"}...)
		session, err := Start(command, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
		Eventually(session).Should(Exit(0))
	})

	Describe("Running init command", func() {
		It("should initialize Starboard", func() {

			crdList, err := apiextensionsClientset.CustomResourceDefinitions().List(context.TODO(), meta.ListOptions{})
			Expect(err).ToNot(HaveOccurred())

			GetNames := func(crds []apiextentions.CustomResourceDefinition) []string {
				names := make([]string, len(crds))
				for i, crd := range crds {
					names[i] = crd.Name
				}
				return names
			}

			Expect(crdList.Items).To(WithTransform(GetNames, ContainElements(
				"ciskubebenchreports.aquasecurity.github.io",
				"configauditreports.aquasecurity.github.io",
				"kubehunterreports.aquasecurity.github.io",
				"vulnerabilities.aquasecurity.github.io",
			)))

			_, err = kubernetesClientset.CoreV1().Namespaces().Get(context.TODO(), "starboard", meta.GetOptions{})
			Expect(err).ToNot(HaveOccurred())

			// TODO Assert other Kubernetes resources that we create in the init command
		})
	})

	Describe("Running version command", func() {
		It("should print the current version of the executable binary", func() {
			command := exec.Command(pathToStarboardCLI, []string{"version"}...)
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session).Should(Say("Starboard Version: {Version:dev Commit:none Date:unknown}\n"))
		})
	})

	Describe("Running kube-bench", func() {
		It("should run kube-bench", func() {
			command := exec.Command(pathToStarboardCLI, "kube-bench", "-v", "3")
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session, scanJobTimeout).Should(Exit(0))

			nodeNames, err := GetNodeNames(context.TODO())
			Expect(err).ToNot(HaveOccurred())

			for _, nodeName := range nodeNames {
				reportList, err := starboardClientset.AquasecurityV1alpha1().CISKubeBenchReports().List(context.TODO(), meta.ListOptions{
					LabelSelector: labels.Set{
						kube.LabelResourceKind: string(kube.KindNode),
						kube.LabelResourceName: nodeName,
					}.String(),
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(HaveLen(1), "Expected CISKubeBenchReport for node %s but not found", nodeName)
			}
		})
	})

	// FIXME Figure out why kube-hunter is failing on GitHub actions runner, whereas it's fine with local KIND cluster
	PDescribe("Running kube-hunter", func() {
		It("should run kube-hunter", func() {
			command := exec.Command(pathToStarboardCLI, "kube-hunter", "-v", "3")
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session, scanJobTimeout).Should(Exit(0))

			report, err := starboardClientset.AquasecurityV1alpha1().KubeHunterReports().
				Get(context.TODO(), "cluster", meta.GetOptions{})

			Expect(err).ToNot(HaveOccurred())
			Expect(report.Labels).To(MatchAllKeys(Keys{
				kube.LabelResourceKind: Equal("Cluster"),
				kube.LabelResourceName: Equal("cluster"),
			}))
		})
	})

	AfterEach(func() {
		command := exec.Command(pathToStarboardCLI, []string{"cleanup", "-v", "3"}...)
		session, err := Start(command, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
		Eventually(session).Should(Exit(0))

		// TODO We have to wait for the termination of the starboard namespace. Otherwise the init command
		// TODO run by the BeforeEach callback fails when it attempts to create Kubernetes objects in the
		// TODO starboard namespace that is being terminated.
		//
		// TODO Maybe the cleanup command should block and wait unit the namespace is terminated?
		Eventually(func() bool {
			_, err := kubernetesClientset.CoreV1().Namespaces().Get(context.TODO(), "starboard", meta.GetOptions{})
			return errors.IsNotFound(err)
		}, 10*time.Second).Should(BeTrue())
	})

})
