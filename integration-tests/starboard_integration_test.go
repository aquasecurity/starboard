package integration_tests

import (
	"context"
	"os/exec"

	apiextentions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	starboardCmd = "./../bin/starboard"
)

var _ = Describe("Starboard CLI", func() {

	BeforeEach(func() {
		// currently do nothing
	})

	Describe("Running version command", func() {
		It("should print the current version of the executable binary", func() {
			cmd := exec.Command(starboardCmd, []string{"version"}...)
			output, err := cmd.Output()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(output)).To(Equal("Starboard Version: {Version:dev Commit:none Date:unknown}\n"))
		})

	})

	Describe("Running init command", func() {
		It("should initialize Starboard", func() {
			cmd := exec.Command(starboardCmd, []string{"init", "-v", "3"}...)
			err := cmd.Run()
			Expect(err).ToNot(HaveOccurred())

			crdsList, err := apiextensionsClientset.CustomResourceDefinitions().List(context.TODO(), meta.ListOptions{})
			Expect(err).ToNot(HaveOccurred())

			GetNames := func(crds []apiextentions.CustomResourceDefinition) []string {
				names := make([]string, len(crds))
				for i, crd := range crds {
					names[i] = crd.Name
				}
				return names
			}

			Expect(crdsList.Items).To(WithTransform(GetNames, ContainElements(
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

	AfterEach(func() {
		// currently do nothing
	})

})
