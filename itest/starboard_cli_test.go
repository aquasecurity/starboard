package itest

import (
	"context"
	"time"

	"github.com/aquasecurity/starboard/pkg/cmd"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/aquasecurity/starboard/pkg/kube"
	. "github.com/onsi/gomega/gstruct"

	apiextentions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Starboard CLI", func() {

	BeforeEach(func() {
		err := cmd.Run(versionInfo, []string{
			"starboard",
			"init",
			"-v",
			starboardCLILogLevel,
		}, GinkgoWriter, GinkgoWriter)

		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Command init", func() {
		It("should initialize Starboard", func() {

			crdList, err := customResourceDefinitions.List(context.TODO(), metav1.ListOptions{})
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

			_, err = namespaces.Get(context.TODO(), "starboard", metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())

			// TODO Assert other Kubernetes resources that we create in the init command
		})
	})

	Describe("Command version", func() {
		It("should print the current version of the executable binary", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"version",
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			// TODO Fix this assert as we no longer use Ginkgo session
			// Eventually(session).Should(Say("Starboard Version: {Version:dev Commit:none Date:unknown}\n"))
		})
	})

	Describe("Command find vulnerabilities", func() {
		// TODO 1. Add test cases for other types of Kubernetes controllers (StatefulSets, DaemonSets, etc.)
		// TODO 2. Add test for a controller with multiple containers

		Context("when unmanaged Pod is specified as workload", func() {

			BeforeEach(func() {
				_, err := defaultPods.Create(context.TODO(), &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: "nginx",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "nginx",
								Image: "nginx:1.16",
							},
						},
					},
				}, metav1.CreateOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create vulnerabilities resource", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "pod/nginx",
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := defaultVulnerabilities.List(context.TODO(), metav1.ListOptions{
					LabelSelector: labels.Set{
						kube.LabelResourceKind: string(kube.KindPod),
						kube.LabelResourceName: "nginx",
					}.String(),
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(HaveLen(1), "Expected VulnerabilityReport for pod/nginx but not found")
			})

			AfterEach(func() {
				err := defaultPods.Delete(context.TODO(), "nginx", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when ReplicaSet is specified as workload", func() {

			BeforeEach(func() {
				_, err := kubernetesClientset.AppsV1().ReplicaSets(corev1.NamespaceDefault).
					Create(context.TODO(), &appsv1.ReplicaSet{
						ObjectMeta: metav1.ObjectMeta{
							Name: "nginx",
						},
						Spec: appsv1.ReplicaSetSpec{
							Replicas: pointer.Int32Ptr(1),
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "nginx"},
							},
							Template: corev1.PodTemplateSpec{
								ObjectMeta: metav1.ObjectMeta{
									Labels: labels.Set{
										"app": "nginx",
									},
								},
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:  "nginx",
											Image: "nginx:1.16",
										},
									},
								},
							},
						},
					}, metav1.CreateOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create vulnerabilities resource", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "replicaset/nginx",
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := defaultVulnerabilities.List(context.TODO(), metav1.ListOptions{
					LabelSelector: labels.Set{
						kube.LabelResourceKind: string(kube.KindReplicaSet),
						kube.LabelResourceName: "nginx",
					}.String(),
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(HaveLen(1), "Expected VulnerabilityReport for replicaset/nginx but not found")
			})

			AfterEach(func() {
				err := kubernetesClientset.AppsV1().ReplicaSets(corev1.NamespaceDefault).
					Delete(context.TODO(), "nginx", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when Deployment is specified as workload", func() {

			BeforeEach(func() {
				_, err := defaultDeployments.Create(context.TODO(), &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name: "nginx",
					},
					Spec: appsv1.DeploymentSpec{
						Replicas: pointer.Int32Ptr(1),
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "nginx"},
						},
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: labels.Set{
									"app": "nginx",
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:  "nginx",
										Image: "nginx:1.16",
									},
								},
							},
						},
					},
				}, metav1.CreateOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create vulnerabilities resource", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "deployment/nginx",
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := defaultVulnerabilities.List(context.TODO(), metav1.ListOptions{
					LabelSelector: labels.Set{
						kube.LabelResourceKind: string(kube.KindDeployment),
						kube.LabelResourceName: "nginx",
					}.String(),
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(HaveLen(1), "Expected VulnerabilityReport for deployment/nginx but not found")
			})

			AfterEach(func() {
				err := defaultDeployments.Delete(context.TODO(), "nginx", metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})
		})

	})

	PDescribe("Command audit configuration", func() {
		// TODO Test polaris command
	})

	Describe("Command run kube-bench", func() {
		It("should run kube-bench", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"kube-bench",
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			nodeNames, err := GetNodeNames(context.TODO())
			Expect(err).ToNot(HaveOccurred())

			for _, nodeName := range nodeNames {
				report, err := starboardClientset.AquasecurityV1alpha1().CISKubeBenchReports().Get(context.TODO(), nodeName, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred(), "Expected CISKubeBenchReport for node %s but not found", nodeName)
				Expect(report.Labels).To(MatchAllKeys(Keys{
					kube.LabelResourceKind:  Equal(string(kube.KindNode)),
					kube.LabelResourceName:  Equal(nodeName),
					kube.LabelHistoryLatest: Equal("true"),
				}))
			}
		})
	})

	PDescribe("Command run kube-hunter", func() {
		// FIXME Figure out why kube-hunter is failing on GitHub actions runner, whereas it's fine with local KIND cluster
		It("should run kube-hunter", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"kube-hunter",
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			report, err := starboardClientset.AquasecurityV1alpha1().KubeHunterReports().
				Get(context.TODO(), "cluster", metav1.GetOptions{})

			Expect(err).ToNot(HaveOccurred())
			Expect(report.Labels).To(MatchAllKeys(Keys{
				kube.LabelResourceKind: Equal("Cluster"),
				kube.LabelResourceName: Equal("cluster"),
			}))
		})
	})

	AfterEach(func() {
		err := cmd.Run(versionInfo, []string{
			"starboard",
			"cleanup",
			"-v",
			starboardCLILogLevel,
		}, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		// TODO We have to wait for the termination of the starboard namespace. Otherwise the init command
		// TODO run by the BeforeEach callback fails when it attempts to create Kubernetes objects in the
		// TODO starboard namespace that is being terminated.
		//
		// TODO Maybe the cleanup command should block and wait unit the namespace is terminated?
		Eventually(func() bool {
			_, err := kubernetesClientset.CoreV1().Namespaces().Get(context.TODO(), "starboard", metav1.GetOptions{})
			return errors.IsNotFound(err)
		}, 10*time.Second).Should(BeTrue())
	})

})
