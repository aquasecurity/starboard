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

	"github.com/aquasecurity/starboard/itest/helper"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

var _ = Describe("Starboard CLI", func() {

	BeforeEach(func() {
		err := cmd.Run(versionInfo, []string{
			"starboard", "install",
			"-v", starboardCLILogLevel,
		}, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Command install", func() {

		It("should initialize Starboard", func() {

			crdList, err := customResourceDefinitions.List(context.TODO(), metav1.ListOptions{})
			Expect(err).ToNot(HaveOccurred())

			groupByName := func(element interface{}) string {
				return element.(apiextensionsv1beta1.CustomResourceDefinition).Name
			}

			Expect(crdList.Items).To(MatchAllElements(groupByName, Elements{
				"vulnerabilityreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "vulnerabilityreports",
							Singular:   "vulnerabilityreport",
							ShortNames: []string{"vuln", "vulns"},
							Kind:       "VulnerabilityReport",
							ListKind:   "VulnerabilityReportList",
							Categories: []string{"all"},
						}),
						"Scope": Equal(apiextensionsv1beta1.NamespaceScoped),
					}),
				}),
				"clustervulnerabilityreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "clustervulnerabilityreports",
							Singular:   "clustervulnerabilityreport",
							ShortNames: []string{"clustervuln", "clustervulns"},
							Kind:       "ClusterVulnerabilityReport",
							ListKind:   "ClusterVulnerabilityReportList",
							Categories: []string{"all"},
						}),
						"Scope": Equal(apiextensionsv1beta1.ClusterScoped),
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
				"clusterconfigauditreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Scope":   Equal(apiextensionsv1beta1.ClusterScoped),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "clusterconfigauditreports",
							Singular:   "clusterconfigauditreport",
							ShortNames: []string{"clusterconfigaudit"},
							Kind:       "ClusterConfigAuditReport",
							ListKind:   "ClusterConfigAuditReportList",
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

			err = kubeClient.Get(context.TODO(), types.NamespacedName{
				Name: starboard.NamespaceName,
			}, &corev1.Namespace{})
			Expect(err).ToNot(HaveOccurred())

			var cm corev1.ConfigMap
			err = kubeClient.Get(context.TODO(), types.NamespacedName{
				Name:      starboard.ConfigMapName,
				Namespace: starboard.NamespaceName,
			}, &cm)

			Expect(err).ToNot(HaveOccurred())
			Expect(cm.Data).To(BeEquivalentTo(starboard.GetDefaultConfig()))

			var secret corev1.Secret
			err = kubeClient.Get(context.TODO(), types.NamespacedName{
				Name:      starboard.SecretName,
				Namespace: starboard.NamespaceName,
			}, &secret)
			Expect(err).ToNot(HaveOccurred())
			Expect(secret.Data).To(Equal(map[string][]byte(nil)))

			err = kubeClient.Get(context.TODO(), types.NamespacedName{
				Name:      starboard.ServiceAccountName,
				Namespace: starboard.NamespaceName,
			}, &corev1.ServiceAccount{})
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

		groupByContainerName := func(element interface{}) string {
			return element.(v1alpha1.VulnerabilityReport).
				Labels[starboard.LabelContainerName]
		}

		Context("when unmanaged Pod is specified as workload", func() {

			var pod *corev1.Pod

			BeforeEach(func() {
				pod = helper.NewPod().WithName("nginx").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					Build()
				err := kubeClient.Create(context.TODO(), pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "pod/" + pod.Name,
					"--namespace", pod.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kube.KindPod),
					starboard.LabelResourceName:      pod.Name,
					starboard.LabelResourceNamespace: pod.Namespace,
				})

				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx-container": IsVulnerabilityReportForContainerOwnedBy("nginx-container", pod),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), pod)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when unmanaged Pod with multiple containers is specified as workload", func() {

			var pod *corev1.Pod

			BeforeEach(func() {
				pod = helper.NewPod().WithName("nginx-and-tomcat").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					WithContainer("tomcat-container", "tomcat:8").
					Build()
				err := kubeClient.Create(context.TODO(), pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReports", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "pod/" + pod.Name,
					"--namespace", pod.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kube.KindPod),
					starboard.LabelResourceName:      pod.Name,
					starboard.LabelResourceNamespace: pod.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx-container":  IsVulnerabilityReportForContainerOwnedBy("nginx-container", pod),
					"tomcat-container": IsVulnerabilityReportForContainerOwnedBy("tomcat-container", pod),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), pod)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		// TODO Run with other integration tests
		// The only reason this test is marked as pending is that I don't know
		// how to pass DockerHub private repository credentials to this test case.
		PContext("when unmanaged Pod with private image is specified as workload", func() {

			var pod *corev1.Pod
			var imagePullSecret *corev1.Secret

			BeforeEach(func() {
				var err error
				imagePullSecret, err = kube.NewImagePullSecret(metav1.ObjectMeta{
					Name:      "registry-credentials",
					Namespace: testNamespace.Name,
				}, "https://index.docker.io/v1",
					os.Getenv("STARBOARD_TEST_DOCKERHUB_REGISTRY_USERNAME"),
					os.Getenv("STARBOARD_TEST_DOCKERHUB_REGISTRY_PASSWORD"))
				Expect(err).ToNot(HaveOccurred())

				err = kubeClient.Create(context.TODO(), imagePullSecret)
				Expect(err).ToNot(HaveOccurred())

				pod = helper.NewPod().WithName("nginx-with-private-image").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "starboardcicd/private-nginx:1.16").
					WithImagePullSecret(imagePullSecret.Name).
					Build()
				err = kubeClient.Create(context.TODO(), pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "po/" + pod.Name,
					"--namespace", pod.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kube.KindPod),
					starboard.LabelResourceName:      pod.Name,
					starboard.LabelResourceNamespace: pod.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx-container": IsVulnerabilityReportForContainerOwnedBy("nginx-container", pod),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), pod)
				Expect(err).ToNot(HaveOccurred())

				err = kubeClient.Delete(context.TODO(), imagePullSecret)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when ReplicaSet is specified as workload", func() {

			var rs *appsv1.ReplicaSet

			BeforeEach(func() {
				var err error
				rs = &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "nginx",
						Namespace: testNamespace.Name,
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
				}
				err = kubeClient.Create(context.TODO(), rs)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "replicaset/" + rs.Name,
					"--namespace", rs.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kube.KindReplicaSet),
					starboard.LabelResourceName:      rs.Name,
					starboard.LabelResourceNamespace: rs.Namespace,
				})

				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", rs),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), rs)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when ReplicationController is specified as workload", func() {

			var rc *corev1.ReplicationController

			BeforeEach(func() {
				var err error
				rc = &corev1.ReplicationController{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "nginx",
						Namespace: testNamespace.Name,
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
				}
				err = kubeClient.Create(context.TODO(), rc)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "rc/" + rc.Name,
					"--namespace", rc.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kube.KindReplicationController),
					starboard.LabelResourceName:      rc.Name,
					starboard.LabelResourceNamespace: rc.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", rc),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), rc)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when Deployment is specified as workload", func() {

			var deploy *appsv1.Deployment

			BeforeEach(func() {
				deploy = helper.NewDeployment().WithName("nginx").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					Build()
				err := kubeClient.Create(context.TODO(), deploy)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "deployment/" + deploy.Name,
					"--namespace", deploy.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kube.KindDeployment),
					starboard.LabelResourceName:      deploy.Name,
					starboard.LabelResourceNamespace: deploy.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"nginx-container": IsVulnerabilityReportForContainerOwnedBy("nginx-container", deploy),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), deploy)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("when StatefulSet is specified as workload", func() {

			var sts *appsv1.StatefulSet

			BeforeEach(func() {
				sts = &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-sts",
						Namespace: testNamespace.Name,
					},
					Spec: appsv1.StatefulSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-sts",
							},
						},
						ServiceName: "test-sts",
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: map[string]string{
									"app": "test-sts",
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:    "test-sts-container",
										Image:   "busybox:1.28",
										Command: []string{"sleep", "5000"},
									},
								},
							},
						},
					},
				}
				err := kubeClient.Create(context.TODO(), sts)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "sts/" + sts.Name,
					"--namespace", sts.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kube.KindStatefulSet),
					starboard.LabelResourceName:      sts.Name,
					starboard.LabelResourceNamespace: sts.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"test-sts-container": IsVulnerabilityReportForContainerOwnedBy("test-sts-container", sts),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), sts)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("when DaemonSet is specified as workload", func() {

			var ds *appsv1.DaemonSet

			BeforeEach(func() {
				ds = &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-ds",
						Namespace: testNamespace.Name,
					},
					Spec: appsv1.DaemonSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-ds",
							},
						},
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: map[string]string{
									"app": "test-ds",
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:    "test-ds-container",
										Image:   "busybox:1.28",
										Command: []string{"sleep", "5000"},
									},
								},
							},
						},
					},
				}
				err := kubeClient.Create(context.TODO(), ds)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "ds/" + ds.Name,
					"--namespace", ds.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kube.KindDaemonSet),
					starboard.LabelResourceName:      ds.Name,
					starboard.LabelResourceNamespace: ds.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"test-ds-container": IsVulnerabilityReportForContainerOwnedBy("test-ds-container", ds),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), ds)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Command get vulnerabilityreports", func() {
		Context("for deployment/nginx resource", func() {
			When("vulnerabilities are associated with the deployment itself", func() {

				var ctx context.Context
				var deploy *appsv1.Deployment
				var report *v1alpha1.VulnerabilityReport

				BeforeEach(func() {
					ctx = context.TODO()
					deploy = helper.NewDeployment().WithName("nginx").
						WithNamespace(testNamespace.Name).
						WithContainer("nginx", "nginx:1.16").
						Build()
					err := kubeClient.Create(ctx, deploy)
					Expect(err).ToNot(HaveOccurred())

					report = helper.NewVulnerabilityReport().WithName("0e1e25ab-8c55-4cdc-af64-21fb8f412cb0").
						WithNamespace(testNamespace.Name).
						WithOwnerKind(kube.KindDeployment).
						WithOwnerName(deploy.Name).
						Build()
					err = kubeClient.Create(ctx, report)
					Expect(err).ToNot(HaveOccurred())
				})

				When("getting vulnerabilities by deployment name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilityreports",
							"deployment/" + deploy.Name,
							"--namespace", deploy.Namespace,
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
					err := kubeClient.Delete(ctx, report)
					Expect(err).ToNot(HaveOccurred())

					err = kubeClient.Delete(ctx, deploy)
					Expect(err).ToNot(HaveOccurred())
				})
			})

			When("vulnerabilities are associated with the managed replicaset", func() {
				var deploy *appsv1.Deployment
				var replicasetName string
				var podName string
				var report *v1alpha1.VulnerabilityReport

				BeforeEach(func() {
					deploy = helper.NewDeployment().WithRandomName("nginx").
						WithNamespace(testNamespace.Name).
						WithContainer("nginx", "nginx:1.16").
						Build()
					err := kubeClient.Create(context.TODO(), deploy)
					Expect(err).ToNot(HaveOccurred())

					replicasetName = ""
					for i := 0; i < 10; i++ {
						var rsList appsv1.ReplicaSetList
						err := kubeClient.List(context.TODO(), &rsList)
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

					podName = ""
					for i := 0; i < 10; i++ {
						var podList corev1.PodList
						err := kubeClient.List(context.TODO(), &podList)
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

					report = helper.NewVulnerabilityReport().WithName("0e1e25ab-8c55-4cdc-af64-21fb8f412cb0").
						WithNamespace(testNamespace.Name).
						WithOwnerKind(kube.KindReplicaSet).
						WithOwnerName(replicasetName).
						Build()
					err = kubeClient.Create(context.TODO(), report)
					Expect(err).ToNot(HaveOccurred())
				})

				When("getting vulnerabilities by deployment name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilities",
							"deployment/" + deploy.Name,
							"--namespace", testNamespace.Name,
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
							"--namespace", testNamespace.Name,
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
							"--namespace", testNamespace.Name,
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
					err := kubeClient.Delete(context.TODO(), report)
					Expect(err).ToNot(HaveOccurred())

					err = kubeClient.Delete(context.TODO(), deploy)
					Expect(err).ToNot(HaveOccurred())
				})
			})
		})
	})

	Describe("Command scan configauditreports", func() {
		var object client.Object

		groupByWorkloadName := func(element interface{}) string {
			return element.(v1alpha1.ConfigAuditReport).
				Labels[starboard.LabelResourceName]
		}

		updateScannerConfig := func(scanner starboard.Scanner) {
			configmap := &corev1.ConfigMap{}
			err := kubeClient.Get(context.Background(), types.NamespacedName{
				Namespace: "starboard",
				Name:      "starboard",
			}, configmap)
			Expect(err).ToNot(HaveOccurred())

			configmapCopy := configmap.DeepCopy()
			configmapCopy.Data["configAuditReports.scanner"] = string(scanner)
			err = kubeClient.Update(context.Background(), configmapCopy)
			Expect(err).ToNot(HaveOccurred())
		}

		assertConfigAuditReportCreated := func(scanner starboard.Scanner, kind kube.Kind) {
			It("should create ConfigAuditReport", func() {
				updateScannerConfig(scanner)
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "configauditreports", strings.ToLower(string(kind)) + "/" + object.GetName(),
					"--namespace", object.GetNamespace(),
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.ConfigAuditReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					starboard.LabelResourceKind:      string(kind),
					starboard.LabelResourceName:      object.GetName(),
					starboard.LabelResourceNamespace: object.GetNamespace(),
				})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByWorkloadName, Elements{
					object.GetName(): IsConfigAuditReportOwnedBy(object, scanner),
				}))
			})
		}

		BeforeEach(func() {
			configmapCopy := conftestConfigMap.DeepCopy()
			err := kubeClient.Create(context.TODO(), configmapCopy)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			err := kubeClient.Delete(context.TODO(), conftestConfigMap)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("when unmanaged Pod is specified as workload", func() {

			var ctx context.Context

			BeforeEach(func() {
				ctx = context.TODO()

				object = helper.NewPod().WithName("nginx-polaris"+"-"+rand.String(5)).
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					Build()
				err := kubeClient.Create(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

			Context("with Polaris as scanner", func() {
				assertConfigAuditReportCreated(starboard.Polaris, kube.KindPod)
			})

			Context("with Conftest as scanner", func() {
				assertConfigAuditReportCreated(starboard.Conftest, kube.KindPod)
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when unmanaged Pod with multiple containers is specified as workload", func() {

			var ctx context.Context

			BeforeEach(func() {
				ctx = context.TODO()
				object = helper.NewPod().WithName("nginx-and-tomcat-starboard"+"-"+rand.String(5)).
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					WithContainer("tomcat-container", "tomcat:8").
					Build()
				err := kubeClient.Create(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

			Context("with Polaris as scanner", func() {
				assertConfigAuditReportCreated(starboard.Polaris, kube.KindPod)
			})

			Context("with Conftest as scanner", func() {
				assertConfigAuditReportCreated(starboard.Conftest, kube.KindPod)
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when CronJob is specified as workload", func() {

			var ctx context.Context
			BeforeEach(func() {
				ctx = context.TODO()
				object = &batchv1beta1.CronJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "hello" + "-" + rand.String(5),
						Namespace: testNamespace.Name,
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
				err := kubeClient.Create(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

			Context("with Polaris as scanner", func() {
				assertConfigAuditReportCreated(starboard.Polaris, kube.KindCronJob)
			})

			Context("with Conftest as scanner", func() {
				assertConfigAuditReportCreated(starboard.Conftest, kube.KindCronJob)
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Command scan ciskubebenchreports", func() {

		It("should create CISKubeBenchReports", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"scan", "ciskubebenchreports",
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			var nodeList corev1.NodeList
			err = kubeClient.List(context.TODO(), &nodeList)
			Expect(err).ToNot(HaveOccurred())

			for _, node := range nodeList.Items {
				var report v1alpha1.CISKubeBenchReport
				err := kubeClient.Get(context.TODO(), types.NamespacedName{Name: node.Name}, &report)
				Expect(err).ToNot(HaveOccurred(), "Expected CISKubeBenchReport for node %s but not found", node.Name)

				// Note: The MatchFieldsMatcher expects struct, not pointer.
				Expect(report).To(MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Labels": MatchAllKeys(Keys{
							starboard.LabelResourceKind: Equal("Node"),
							starboard.LabelResourceName: Equal(node.Name),
						}),
						"OwnerReferences": ConsistOf(metav1.OwnerReference{
							APIVersion:         "v1",
							Kind:               "Node",
							Name:               node.Name,
							UID:                node.UID,
							Controller:         pointer.BoolPtr(true),
							BlockOwnerDeletion: pointer.BoolPtr(false),
						}),
					}),
					"Report": MatchFields(IgnoreExtras, Fields{
						"Scanner": Equal(v1alpha1.Scanner{
							Name:    "kube-bench",
							Vendor:  "Aqua Security",
							Version: "0.6.3",
						}),
					}),
				}))
			}
		})
	})

	Describe("Command scan kubehunterreports", func() {

		BeforeEach(func() {
			var cm corev1.ConfigMap
			err := kubeClient.Get(context.TODO(), types.NamespacedName{
				Name:      starboard.ConfigMapName,
				Namespace: starboard.NamespaceName,
			}, &cm)
			Expect(err).ToNot(HaveOccurred())

			// Need to use kube-hunter quick scanning mode (subnet 24), otherwise
			// when running the test in Azure (e.g., in a GitHub actions runner)
			// kube-hunter may attempt to scan a large CIDR (subnet 16), which takes a long
			// time and isn't necessary for the purposes of the test.
			cm.Data["kube-hunter.quick"] = "true"
			err = kubeClient.Update(context.TODO(), &cm)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should create KubeHunterReport", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"scan", "kubehunterreports",
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			var report v1alpha1.KubeHunterReport
			err = kubeClient.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, &report)
			Expect(err).ToNot(HaveOccurred())
			Expect(report.Labels).To(MatchAllKeys(Keys{
				starboard.LabelResourceKind: Equal("Cluster"),
				starboard.LabelResourceName: Equal("cluster"),
			}))
		})
	})

	AfterEach(func() {
		err := cmd.Run(versionInfo, []string{
			"starboard",
			"uninstall",
			"-v", starboardCLILogLevel,
		}, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
	})

})
