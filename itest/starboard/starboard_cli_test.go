package starboard

import (
	. "github.com/aquasecurity/starboard/itest/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gstruct"

	"context"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/cmd"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// NewPodSpec returns the creation a pod spec
func NewPodSpec(podName string, containers map[string]string, args ...string) (*corev1.Pod, error) {

	var specContainer []corev1.Container
	for k, v := range containers {
		specContainer = append(specContainer, corev1.Container{
			Name:            k,
			Image:           v,
			ImagePullPolicy: corev1.PullIfNotPresent,
		})
	}

	var secretSpec []corev1.LocalObjectReference
	if len(args) > 1 {
		secretSpec = []corev1.LocalObjectReference{
			{
				Name: args[0],
			},
		}
	}

	pod, err := kubernetesClientset.CoreV1().Pods(namespaceItest).
		Create(context.TODO(), &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: namespaceItest,
			},
			Spec: corev1.PodSpec{
				Containers:       specContainer,
				ImagePullSecrets: secretSpec,
			},
		}, metav1.CreateOptions{})
	return pod, err
}

var (
	trivyScanner = v1alpha1.Scanner{
		Name:    "Trivy",
		Vendor:  "Aqua Security",
		Version: "0.16.0",
	}
)

var _ = Describe("Starboard CLI", func() {

	BeforeEach(func() {
		err := cmd.Run(versionInfo, []string{
			"starboard",
			"init",
			"-v", starboardCLILogLevel,
		}, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Command init", func() {

		It("should initialize Starboard", func() {

			crdList, err := customResourceDefinitions.List(context.TODO(), metav1.ListOptions{})
			Expect(err).ToNot(HaveOccurred())

			id := func(element interface{}) string {
				return element.(apiextensionsv1beta1.CustomResourceDefinition).Name
			}

			Expect(crdList.Items).To(MatchAllElements(id, Elements{
				"vulnerabilityreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "vulnerabilityreports",
							Singular:   "vulnerabilityreport",
							ShortNames: []string{"vulns", "vuln"},
							Kind:       "VulnerabilityReport",
							ListKind:   "VulnerabilityReportList",
							Categories: []string{"all"},
						}),
						"Scope": Equal(apiextensionsv1beta1.NamespaceScoped),
					}),
				}),
				"configauditreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Scope":   Equal(apiextensionsv1beta1.NamespaceScoped),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "configauditreports",
							Singular:   "configauditreport",
							ShortNames: []string{"configaudit"},
							Kind:       "ConfigAuditReport",
							ListKind:   "ConfigAuditReportList",
							Categories: []string{"all"},
						}),
					}),
				}),
				"ciskubebenchreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Scope":   Equal(apiextensionsv1beta1.ClusterScoped),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "ciskubebenchreports",
							Singular:   "ciskubebenchreport",
							ShortNames: []string{"kubebench"},
							Kind:       "CISKubeBenchReport",
							ListKind:   "CISKubeBenchReportList",
							Categories: []string{"all"},
						}),
					}),
				}),
				"kubehunterreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Scope":   Equal(apiextensionsv1beta1.ClusterScoped),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "kubehunterreports",
							Singular:   "kubehunterreport",
							ShortNames: []string{"kubehunter"},
							Kind:       "KubeHunterReport",
							ListKind:   "KubeHunterReportList",
							Categories: []string{"all"},
						}),
					}),
				}),
			}))

			_, err = namespaces.Get(context.TODO(), starboard.NamespaceName, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())

			cm, err := kubernetesClientset.CoreV1().ConfigMaps(starboard.NamespaceName).
				Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(cm.Data).To(BeEquivalentTo(starboard.GetDefaultConfig()))

			secret, err := kubernetesClientset.CoreV1().Secrets(starboard.NamespaceName).
				Get(context.TODO(), starboard.SecretName, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(secret.Data).To(Equal(map[string][]byte(nil)))

			_, err = kubernetesClientset.CoreV1().ServiceAccounts(starboard.NamespaceName).
				Get(context.TODO(), starboard.ServiceAccountName, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("Command version", func() {

		It("should print the current version of the executable binary", func() {
			out := NewBuffer()
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"version",
			}, out, out)
			Expect(err).ToNot(HaveOccurred())
			Eventually(out).Should(Say("Starboard Version: {Version:dev Commit:none Date:unknown}"))
		})

	})

	Describe("Command scan vulnerabilityreports", func() {
		// TODO 1. Add test cases for other types of Kubernetes controllers (StatefulSets, DaemonSets, etc.)

		groupByContainerName := func(element interface{}) string {
			return element.(v1alpha1.VulnerabilityReport).
				Labels[kube.LabelContainerName]
		}

		Context("when unmanaged Pod is specified as workload", func() {
			var pod *corev1.Pod
			var podName = "nginx"
			var podNamespace = namespaceItest
			containers := map[string]string{"nginx": "nginx:1.16"}

			BeforeEach(func() {
				var err error
				pod, err = NewPodSpec(podName, containers)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "pod/" + podName,
					"-v", starboardCLILogLevel, "--namespace", namespaceItest,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(podNamespace).
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind:      "Pod",
							kube.LabelResourceName:      podName,
							kube.LabelResourceNamespace: podNamespace,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", pod),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.CoreV1().Pods(podNamespace).
					Delete(context.TODO(), podName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when unmanaged Pod with multiple containers is specified as workload", func() {
			var pod *corev1.Pod
			var podName = "nginx-and-tomcat"
			var podNamespace = namespaceItest
			containers := map[string]string{"nginx": "nginx:1.16", "tomcat": "tomcat:8"}

			BeforeEach(func() {
				var err error
				pod, err = NewPodSpec(podName, containers)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create vulnerabilities resources", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "pod/" + podName,
					"-v", starboardCLILogLevel, "--namespace", namespaceItest,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(podNamespace).
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind:      "Pod",
							kube.LabelResourceName:      podName,
							kube.LabelResourceNamespace: podNamespace,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx":  IsVulnerabilityReportForContainerOwnedBy("nginx", pod),
					"tomcat": IsVulnerabilityReportForContainerOwnedBy("tomcat", pod),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.CoreV1().Pods(podNamespace).
					Delete(context.TODO(), podName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		// TODO Run with other integration tests
		// The only reason this test is marked as pending is that I don't know
		// how to pass DockerHub private repository credentials to this test case.
		PContext("when unmanaged Pod with private image is specified as workload", func() {
			var pod *corev1.Pod

			var podName = "nginx-with-private-image"
			var secretName = "registry-credentials"
			var podNamespace = namespaceItest
			containers := map[string]string{"nginx": "starboardcicd/private-nginx:1.16"}

			BeforeEach(func() {
				var err error
				var secret *corev1.Secret
				secret, err = kube.NewImagePullSecret(metav1.ObjectMeta{
					Name:      secretName,
					Namespace: podNamespace,
				}, "https://index.docker.io/v1",
					os.Getenv("STARBOARD_TEST_DOCKERHUB_REGISTRY_USERNAME"),
					os.Getenv("STARBOARD_TEST_DOCKERHUB_REGISTRY_PASSWORD"))
				Expect(err).ToNot(HaveOccurred())

				_, err = kubernetesClientset.CoreV1().Secrets(podNamespace).
					Create(context.TODO(), secret, metav1.CreateOptions{})
				Expect(err).ToNot(HaveOccurred())

				pod, err = NewPodSpec(podName, containers, []string{secretName}...)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create vulnerabilities resources", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "po/nginx-with-private-image",
					"-v", starboardCLILogLevel, "--namespace", namespaceItest,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(podNamespace).
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind:      "Pod",
							kube.LabelResourceName:      podName,
							kube.LabelResourceNamespace: podNamespace,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", pod),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.CoreV1().Pods(podNamespace).
					Delete(context.TODO(), podName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())

				err = kubernetesClientset.CoreV1().Secrets(podNamespace).
					Delete(context.TODO(), secretName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when ReplicaSet is specified as workload", func() {
			var rs *appsv1.ReplicaSet
			var rsName = "nginx"
			var rsNamespace = namespaceItest

			BeforeEach(func() {
				var err error
				rs, err = kubernetesClientset.AppsV1().ReplicaSets(rsNamespace).
					Create(context.TODO(), &appsv1.ReplicaSet{
						ObjectMeta: metav1.ObjectMeta{
							Name:      rsName,
							Namespace: rsNamespace,
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
					"-v", starboardCLILogLevel, "--namespace", namespaceItest,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(rsNamespace).
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind:      "ReplicaSet",
							kube.LabelResourceName:      rsName,
							kube.LabelResourceNamespace: rsNamespace,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", rs),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.AppsV1().ReplicaSets(rsNamespace).
					Delete(context.TODO(), rsName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when ReplicationController is specified as workload", func() {
			var rc *corev1.ReplicationController
			var rcName = "nginx"
			var rcNamespace = namespaceItest

			BeforeEach(func() {
				var err error
				rc, err = kubernetesClientset.CoreV1().ReplicationControllers(rcNamespace).
					Create(context.TODO(), &corev1.ReplicationController{
						ObjectMeta: metav1.ObjectMeta{
							Name:      rcName,
							Namespace: rcNamespace,
						},
						Spec: corev1.ReplicationControllerSpec{
							Replicas: pointer.Int32Ptr(1),
							Selector: map[string]string{
								"app": "nginx",
							},
							Template: &corev1.PodTemplateSpec{
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
					"find", "vulnerabilities", "rc/nginx",
					"-v", starboardCLILogLevel, "--namespace", namespaceItest,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(rcNamespace).
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind:      "ReplicationController",
							kube.LabelResourceName:      rcName,
							kube.LabelResourceNamespace: rcNamespace,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", rc),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.CoreV1().ReplicationControllers(rcNamespace).
					Delete(context.TODO(), rcName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when Deployment is specified as workload", func() {
			var deploy *appsv1.Deployment
			var deployName = "nginx"
			var deployNamespace = namespaceItest

			BeforeEach(func() {
				var err error
				deploy, err = kubernetesClientset.AppsV1().Deployments(deployNamespace).
					Create(context.TODO(), &appsv1.Deployment{
						ObjectMeta: metav1.ObjectMeta{
							Name:      deployName,
							Namespace: deployNamespace,
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
					"-v", starboardCLILogLevel, "--namespace", namespaceItest,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(deployNamespace).
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind:      "Deployment",
							kube.LabelResourceName:      deployName,
							kube.LabelResourceNamespace: deployNamespace,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", deploy),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.AppsV1().Deployments(deployNamespace).
					Delete(context.TODO(), deployName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})
		})

	})

	Describe("Command get vulnerabilities", func() {
		Context("for deployment/nginx resource", func() {
			When("vulnerabilities are associated with the deployment itself", func() {
				ctx := context.TODO()
				var deploy *appsv1.Deployment
				var report *v1alpha1.VulnerabilityReport
				BeforeEach(func() {
					deploy = makeDeployment("nginx:1.16")
					report = makeReport(kube.KindDeployment, deploy.Name)
					_, err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(namespaceItest).Create(ctx, report, metav1.CreateOptions{})
					Expect(err).ToNot(HaveOccurred())
				})

				When("getting vulnerabilities by deployment name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilities",
							"deployment/" + deploy.Name,
							"--namespace", namespaceItest,
							"-v", starboardCLILogLevel,
						}, stdout, stderr)
						Expect(err).ToNot(HaveOccurred())

						var list v1alpha1.VulnerabilityReportList
						err = yaml.Unmarshal(stdout.Contents(), &list)
						Expect(err).ToNot(HaveOccurred())

						if Expect(len(list.Items)).To(Equal(1)) {
							item := list.Items[0]
							item.Report.UpdateTimestamp = report.Report.UpdateTimestamp // TODO A Hack to skip comparing timestamp
							Expect(item.Report).To(Equal(report.Report))
						}

						Expect(stderr).Should(Say(""))
					})
				})

				AfterEach(func() {
					err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(namespaceItest).Delete(ctx, report.Name, metav1.DeleteOptions{})
					Expect(err).ToNot(HaveOccurred())
				})
			})

			When("vulnerabilities are associated with the managed replicaset", func() {
				ctx := context.TODO()
				var deploy *appsv1.Deployment
				var replicasetName string
				var podName string
				var report *v1alpha1.VulnerabilityReport

				BeforeEach(func() {
					deploy = makeDeployment("nginx:1.16")
					_, err := kubernetesClientset.AppsV1().Deployments(namespaceItest).Create(ctx, deploy, metav1.CreateOptions{})
					Expect(err).ToNot(HaveOccurred())

					for i := 0; i < 10; i++ {
						rsList, err := kubernetesClientset.AppsV1().ReplicaSets(namespaceItest).List(ctx, metav1.ListOptions{})
						Expect(err).ToNot(HaveOccurred())
						if len(rsList.Items) > 0 {
							for _, rs := range rsList.Items {
								for _, ownerRef := range rs.OwnerReferences {
									if ownerRef.Name == deploy.Name && *ownerRef.Controller {
										replicasetName = rs.Name
									}
								}
							}
							if replicasetName != "" {
								break
							}
						}
						time.Sleep(time.Second)
					}
					Expect(replicasetName).ToNot(BeEmpty())

					for i := 0; i < 10; i++ {
						podList, err := kubernetesClientset.CoreV1().Pods(namespaceItest).List(ctx, metav1.ListOptions{})
						Expect(err).ToNot(HaveOccurred())
						if len(podList.Items) > 0 {
							for _, pod := range podList.Items {
								for _, ownerRef := range pod.OwnerReferences {
									if ownerRef.Name == replicasetName && *ownerRef.Controller {
										podName = pod.Name
									}
								}
							}
							if podName != "" {
								break
							}
						}
						time.Sleep(time.Second)
					}
					Expect(podName).ToNot(BeEmpty())

					report = makeReport(kube.KindReplicaSet, replicasetName)
					_, err = starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(namespaceItest).Create(ctx, report, metav1.CreateOptions{})
					Expect(err).ToNot(HaveOccurred())
				})

				When("getting vulnerabilities by deployment name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilities",
							"deployment/" + deploy.Name,
							"--namespace", namespaceItest,
							"-v", starboardCLILogLevel,
						}, stdout, stderr)
						Expect(err).ToNot(HaveOccurred())

						var list v1alpha1.VulnerabilityReportList
						err = yaml.Unmarshal(stdout.Contents(), &list)
						Expect(err).ToNot(HaveOccurred())

						if Expect(len(list.Items)).To(Equal(1)) {
							item := list.Items[0]
							item.Report.UpdateTimestamp = report.Report.UpdateTimestamp // TODO A Hack to skip comparing timestamp
							Expect(item.Report).To(Equal(report.Report))
						}

						Expect(stderr).Should(Say(""))
					})
				})

				When("getting vulnerabilities by replicaset name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilities",
							"replicaset/" + replicasetName,
							"--namespace", namespaceItest,
							"-v", starboardCLILogLevel,
						}, stdout, stderr)
						Expect(err).ToNot(HaveOccurred())

						var list v1alpha1.VulnerabilityReportList
						err = yaml.Unmarshal(stdout.Contents(), &list)
						Expect(err).ToNot(HaveOccurred())

						if Expect(len(list.Items)).To(Equal(1)) {
							item := list.Items[0]
							item.Report.UpdateTimestamp = report.Report.UpdateTimestamp // TODO A Hack to skip comparing timestamp
							Expect(item.Report).To(Equal(report.Report))
						}

						Expect(stderr).Should(Say(""))
					})
				})

				When("getting vulnerabilities by pod name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilities",
							"pod/" + podName,
							"--namespace", namespaceItest,
							"-v", starboardCLILogLevel,
						}, stdout, stderr)
						Expect(err).ToNot(HaveOccurred())

						var list v1alpha1.VulnerabilityReportList
						err = yaml.Unmarshal(stdout.Contents(), &list)
						Expect(err).ToNot(HaveOccurred())

						if Expect(len(list.Items)).To(Equal(1)) {
							item := list.Items[0]
							item.Report.UpdateTimestamp = report.Report.UpdateTimestamp // TODO A Hack to skip comparing timestamp
							Expect(item.Report).To(Equal(report.Report))
						}

						Expect(stderr).Should(Say(""))
					})
				})

				AfterEach(func() {
					err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(namespaceItest).Delete(ctx, report.Name, metav1.DeleteOptions{})
					Expect(err).ToNot(HaveOccurred())
					err = kubernetesClientset.AppsV1().Deployments(namespaceItest).Delete(ctx, deploy.Name, metav1.DeleteOptions{})
					Expect(err).ToNot(HaveOccurred())
				})
			})
		})
	})

	Describe("Command scan configauditreports", func() {

		groupByWorkloadName := func(element interface{}) string {
			return element.(v1alpha1.ConfigAuditReport).
				Labels[kube.LabelResourceName]
		}

		Context("when unmanaged Pod is specified as workload", func() {
			var pod *corev1.Pod
			var podName = "nginx-polaris"
			var podNamespace = namespaceItest
			containers := map[string]string{"nginx": "nginx:1.16"}

			BeforeEach(func() {
				var err error
				pod, err = NewPodSpec(podName, containers)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create ConfigAuditReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "configauditreports", "pod/" + podName,
					"--namespace", namespaceItest,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := starboardClientset.AquasecurityV1alpha1().ConfigAuditReports(podNamespace).
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind:      "Pod",
							kube.LabelResourceName:      podName,
							kube.LabelResourceNamespace: podNamespace,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByWorkloadName, Elements{
					podName: IsConfigAuditReportOwnedBy(pod),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.CoreV1().Pods(podNamespace).
					Delete(context.TODO(), podName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when unmanaged Pod with multiple containers is specified as workload", func() {
			var pod *corev1.Pod
			var podName = "nginx-and-tomcat-starboard"
			var podNamespace = namespaceItest
			containers := map[string]string{"nginx": "nginx:1.16", "tomcat": "tomcat:8"}

			BeforeEach(func() {
				var err error
				pod, err = NewPodSpec(podName, containers)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create ConfigAuditReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "configauditreports", "pod/" + podName,
					"--namespace", namespaceItest,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reportList, err := starboardClientset.AquasecurityV1alpha1().ConfigAuditReports(podNamespace).
					List(context.TODO(), metav1.ListOptions{
						LabelSelector: labels.Set{
							kube.LabelResourceKind:      "Pod",
							kube.LabelResourceName:      podName,
							kube.LabelResourceNamespace: podNamespace,
						}.String(),
					})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByWorkloadName, Elements{
					podName: IsConfigAuditReportOwnedBy(pod),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.CoreV1().Pods(podNamespace).
					Delete(context.TODO(), podName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when CronJob is specified as workload", func() {

			var cronJob *batchv1beta1.CronJob

			BeforeEach(func() {
				cronJob = &batchv1beta1.CronJob{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespaceItest,
						Name:      "hello",
					},
					Spec: batchv1beta1.CronJobSpec{
						Schedule: "*/1 * * * *",
						JobTemplate: batchv1beta1.JobTemplateSpec{
							Spec: batchv1.JobSpec{
								Template: corev1.PodTemplateSpec{
									Spec: corev1.PodSpec{
										RestartPolicy: corev1.RestartPolicyOnFailure,
										Containers: []corev1.Container{
											{
												Name:  "hello",
												Image: "busybox",
												Command: []string{
													"/bin/sh",
													"-c",
													"date; echo Hello from the Kubernetes cluster",
												},
											},
										},
									},
								},
							},
						},
					},
				}
				err := kubeClient.Create(context.Background(), cronJob)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create ConfigAuditReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "configauditreports", "cronjob/hello",
					"--namespace", namespaceItest,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.ConfigAuditReportList

				err = kubeClient.List(context.Background(), &reportList, client.MatchingLabels{
					kube.LabelResourceKind:      string(kube.KindCronJob),
					kube.LabelResourceName:      cronJob.Name,
					kube.LabelResourceNamespace: cronJob.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByWorkloadName, Elements{
					"hello": IsConfigAuditReportOwnedBy(cronJob),
				}))

			})

			AfterEach(func() {
				err := kubeClient.Delete(context.Background(), cronJob)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Command scan ciskubebenchreports", func() {

		It("should run kube-bench", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"generate",
				"ciskubebenchreports",
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			nodeList, err := kubernetesClientset.CoreV1().Nodes().
				List(context.TODO(), metav1.ListOptions{})
			Expect(err).ToNot(HaveOccurred())

			for _, node := range nodeList.Items {
				report, err := starboardClientset.AquasecurityV1alpha1().CISKubeBenchReports().
					Get(context.TODO(), node.Name, metav1.GetOptions{})
				Expect(err).ToNot(HaveOccurred(), "Expected CISKubeBenchReport for node %s but not found", node.Name)

				// Note: The MatchFieldsMatcher expects struct, not pointer.
				Expect(*report).To(MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Labels": MatchAllKeys(Keys{
							kube.LabelResourceKind: Equal("Node"),
							kube.LabelResourceName: Equal(node.Name),
						}),
						"OwnerReferences": ConsistOf(metav1.OwnerReference{
							APIVersion:         "v1",
							Kind:               "Node",
							Name:               node.Name,
							UID:                node.UID,
							Controller:         pointer.BoolPtr(true),
							BlockOwnerDeletion: pointer.BoolPtr(true),
						}),
					}),
					"Report": MatchFields(IgnoreExtras, Fields{
						"Scanner": Equal(v1alpha1.Scanner{
							Name:    "kube-bench",
							Vendor:  "Aqua Security",
							Version: "0.5.0",
						}),
					}),
				}))
			}
		})
	})

	Describe("Command scan kubehunterreports", func() {
		BeforeEach(func() {
			cm, err := kubernetesClientset.CoreV1().ConfigMaps(starboard.NamespaceName).
				Get(context.TODO(), starboard.ConfigMapName, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())

			// Need to use kube-hunter quick scanning mode (subnet 24), otherwise
			// when running the test in Azure (e.g., in a GitHub actions runner)
			// kube-hunter may attempt to scan a large CIDR (subnet 16), which takes a long
			// time and isn't necessary for the purposes of the test.
			cm.Data["kube-hunter.quick"] = "true"
			_, err = kubernetesClientset.CoreV1().ConfigMaps(starboard.NamespaceName).
				Update(context.TODO(), cm, metav1.UpdateOptions{})
			Expect(err).ToNot(HaveOccurred())
		})

		It("should run kube-hunter", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"scan",
				"kubehunterreports",
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
	})

})

func makeDeployment(image string) *appsv1.Deployment {
	name := strings.Split(image, ":")[0]
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespaceItest,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: pointer.Int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels.Set{
						"app": name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  name,
							Image: image,
						},
					},
				},
			},
		},
	}
}

func makeReport(kind kube.Kind, name string) *v1alpha1.VulnerabilityReport {
	return &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "0e1e25ab-8c55-4cdc-af64-21fb8f412cb0",
			Namespace: namespaceItest,
			Labels: map[string]string{
				"starboard.container.name":     "nginx",
				"starboard.resource.kind":      string(kind),
				"starboard.resource.name":      name,
				"starboard.resource.namespace": namespaceItest,
			},
		},
		Report: v1alpha1.VulnerabilityScanResult{
			UpdateTimestamp: metav1.NewTime(time.Now()),
			Scanner:         trivyScanner,
			Registry: v1alpha1.Registry{
				Server: "index.docker.io",
			},
			Artifact: v1alpha1.Artifact{
				Repository: "library/nginx",
				Tag:        "1.16",
			},
			Summary: v1alpha1.VulnerabilitySummary{
				MediumCount: 1,
			},
			Vulnerabilities: []v1alpha1.Vulnerability{
				{
					VulnerabilityID:  "CVE-2020-3810",
					Resource:         "apt",
					InstalledVersion: "1.8.2",
					FixedVersion:     "1.8.2.1",
					Severity:         v1alpha1.SeverityMedium,
					Title:            "",
					Description:      "Missing input validation in the ar/tar implementations of APT before version 2.1.2 could result in denial of service when processing specially crafted deb files.",
					Links: []string{
						"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3810",
					},
				},
			},
		},
	}
}
