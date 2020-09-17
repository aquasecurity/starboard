package itest

import (
	"context"
	"os"

	"github.com/aquasecurity/starboard/pkg/kube/secrets"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"

	. "github.com/onsi/gomega/gbytes"

	"github.com/aquasecurity/starboard/pkg/cmd"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/aquasecurity/starboard/pkg/kube"
	. "github.com/onsi/gomega/gstruct"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// NewPodSpec returns the creation a pod spec
func NewPodSpec(podNamespace, podName string, containers map[string]string, args ...string) (*corev1.Pod, error) {

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

	pod, err := kubernetesClientset.CoreV1().Pods(podNamespace).
		Create(context.TODO(), &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: podNamespace,
			},
			Spec: corev1.PodSpec{
				Containers:       specContainer,
				ImagePullSecrets: secretSpec,
			},
		}, metav1.CreateOptions{})
	return pod, err
}

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

			_, err = namespaces.Get(context.TODO(), "starboard", metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())

			// TODO Assert other Kubernetes resources that we create in the init command
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

	Describe("Command find vulnerabilities", func() {
		// TODO 1. Add test cases for other types of Kubernetes controllers (StatefulSets, DaemonSets, etc.)

		// containerNameAsIdFn is used as an identifier by the MatchAllElements matcher
		// to group Vulnerability reports by container name.
		containerNameAsIdFn := func(element interface{}) string {
			return element.(v1alpha1.VulnerabilityReport).
				Labels[kube.LabelContainerName]
		}

		Context("when unmanaged Pod is specified as workload", func() {
			var pod *corev1.Pod
			var podName = "nginx"
			var podNamespace = corev1.NamespaceDefault
			containers := map[string]string{"nginx": "nginx:1.16"}

			BeforeEach(func() {
				var err error
				pod, err = NewPodSpec(podNamespace, podName, containers)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create vulnerabilities resource", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "pod/" + podName,
					"-v", starboardCLILogLevel,
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

				Expect(reportList.Items).To(MatchAllElements(containerNameAsIdFn, Elements{
					"nginx": MatchFields(IgnoreExtras, Fields{
						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelContainerName:     Equal(podName),
								kube.LabelResourceKind:      Equal("Pod"),
								kube.LabelResourceName:      Equal(podName),
								kube.LabelResourceNamespace: Equal(podNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "v1",
								Kind:       "Pod",
								Name:       podName,
								UID:        pod.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Trivy",
								Vendor:  "Aqua Security",
								Version: "0.9.1",
							}),
						}),
					}),
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
			var podNamespace = corev1.NamespaceDefault
			containers := map[string]string{"nginx": "nginx:1.16", "tomcat": "tomcat:8"}

			BeforeEach(func() {
				var err error
				pod, err = NewPodSpec(podNamespace, podName, containers)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create vulnerabilities resources", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "pod/" + podName,
					"-v", starboardCLILogLevel,
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

				Expect(reportList.Items).To(MatchAllElements(containerNameAsIdFn, Elements{
					"nginx": MatchFields(IgnoreExtras, Fields{
						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelContainerName:     Equal("nginx"),
								kube.LabelResourceKind:      Equal("Pod"),
								kube.LabelResourceName:      Equal(podName),
								kube.LabelResourceNamespace: Equal(podNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "v1",
								Kind:       "Pod",
								Name:       podName,
								UID:        pod.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Trivy",
								Vendor:  "Aqua Security",
								Version: "0.9.1",
							}),
						}),
					}),
					"tomcat": MatchFields(IgnoreExtras, Fields{
						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelContainerName:     Equal("tomcat"),
								kube.LabelResourceKind:      Equal("Pod"),
								kube.LabelResourceName:      Equal(podName),
								kube.LabelResourceNamespace: Equal(podNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "v1",
								Kind:       "Pod",
								Name:       podName,
								UID:        pod.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Trivy",
								Vendor:  "Aqua Security",
								Version: "0.9.1",
							}),
						}),
					}),
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
			var podNamespace = corev1.NamespaceDefault
			containers := map[string]string{"nginx": "starboardcicd/private-nginx:1.16"}

			BeforeEach(func() {
				var err error
				var secret *corev1.Secret
				secret, err = secrets.NewImagePullSecret(metav1.ObjectMeta{
					Name:      secretName,
					Namespace: podNamespace,
				}, "https://index.docker.io/v1",
					os.Getenv("STARBOARD_TEST_DOCKERHUB_REGISTRY_USERNAME"),
					os.Getenv("STARBOARD_TEST_DOCKERHUB_REGISTRY_PASSWORD"))
				Expect(err).ToNot(HaveOccurred())

				_, err = kubernetesClientset.CoreV1().Secrets(podNamespace).
					Create(context.TODO(), secret, metav1.CreateOptions{})
				Expect(err).ToNot(HaveOccurred())

				pod, err = NewPodSpec(podNamespace, podName, containers, []string{secretName}...)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create vulnerabilities resources", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"find", "vulnerabilities", "po/nginx-with-private-image",
					"-v", starboardCLILogLevel,
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

				Expect(reportList.Items).To(MatchAllElements(containerNameAsIdFn, Elements{
					"nginx": MatchFields(IgnoreExtras, Fields{
						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelContainerName:     Equal("nginx"),
								kube.LabelResourceKind:      Equal("Pod"),
								kube.LabelResourceName:      Equal(podName),
								kube.LabelResourceNamespace: Equal(podNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "v1",
								Kind:       "Pod",
								Name:       podName,
								UID:        pod.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Trivy",
								Vendor:  "Aqua Security",
								Version: "0.9.1",
							}),
						}),
					}),
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
			var rsNamespace = corev1.NamespaceDefault

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
					"-v", starboardCLILogLevel,
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

				Expect(reportList.Items).To(MatchAllElements(containerNameAsIdFn, Elements{
					"nginx": MatchFields(IgnoreExtras, Fields{
						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelContainerName:     Equal("nginx"),
								kube.LabelResourceKind:      Equal("ReplicaSet"),
								kube.LabelResourceName:      Equal(rsName),
								kube.LabelResourceNamespace: Equal(rsNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "apps/v1",
								Kind:       "ReplicaSet",
								Name:       rsName,
								UID:        rs.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Trivy",
								Vendor:  "Aqua Security",
								Version: "0.9.1",
							}),
						}),
					}),
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
			var rcNamespace = corev1.NamespaceDefault

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
					"-v", starboardCLILogLevel,
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

				Expect(reportList.Items).To(MatchAllElements(containerNameAsIdFn, Elements{
					"nginx": MatchFields(IgnoreExtras, Fields{
						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelContainerName:     Equal("nginx"),
								kube.LabelResourceKind:      Equal("ReplicationController"),
								kube.LabelResourceName:      Equal(rcName),
								kube.LabelResourceNamespace: Equal(rcNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "v1",
								Kind:       "ReplicationController",
								Name:       rcName,
								UID:        rc.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Trivy",
								Vendor:  "Aqua Security",
								Version: "0.9.1",
							}),
						}),
					}),
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
			var deployNamespace = corev1.NamespaceDefault

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
					"-v", starboardCLILogLevel,
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

				Expect(reportList.Items).To(MatchAllElements(containerNameAsIdFn, Elements{
					"nginx": MatchFields(IgnoreExtras, Fields{
						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelContainerName:     Equal("nginx"),
								kube.LabelResourceKind:      Equal("Deployment"),
								kube.LabelResourceName:      Equal(deployName),
								kube.LabelResourceNamespace: Equal(deployNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "apps/v1",
								Kind:       "Deployment",
								Name:       deployName,
								UID:        deploy.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Trivy",
								Vendor:  "Aqua Security",
								Version: "0.9.1",
							}),
						}),
					}),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.AppsV1().Deployments(deployNamespace).
					Delete(context.TODO(), deployName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})
		})

	})

	Describe("Command polaris", func() {
		// containerNameAsIDFn is used as an identifier by the MatchAllElements matcher
		// to group ConfigAuditReport by container name.
		resourceNameAsIDFn := func(element interface{}) string {
			return element.(v1alpha1.ConfigAuditReport).
				Labels[kube.LabelResourceName]
		}

		Context("when unmanaged Pod is specified as workload", func() {
			var pod *corev1.Pod
			var podName = "nginx-polaris"
			var podNamespace = corev1.NamespaceDefault
			containers := map[string]string{"nginx": "nginx:1.16"}

			BeforeEach(func() {
				var err error
				pod, err = NewPodSpec(podNamespace, podName, containers)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create configaudit resource", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"polaris", "pod/" + podName,
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

				Expect(reportList.Items).To(MatchAllElements(resourceNameAsIDFn, Elements{
					podName: MatchFields(IgnoreExtras, Fields{
						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelResourceKind:      Equal("Pod"),
								kube.LabelResourceName:      Equal(podName),
								kube.LabelResourceNamespace: Equal(podNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "v1",
								Kind:       "Pod",
								Name:       podName,
								UID:        pod.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Polaris",
								Vendor:  "Fairwinds Ops",
								Version: "1.2",
							}),
						}),
					}),
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
			var podNamespace = corev1.NamespaceDefault
			containers := map[string]string{"nginx": "nginx:1.16", "tomcat": "tomcat:8"}

			BeforeEach(func() {
				var err error
				pod, err = NewPodSpec(podNamespace, podName, containers)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create configaudit resources", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"polaris", "pod/" + podName,
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

				Expect(reportList.Items).To(MatchAllElements(resourceNameAsIDFn, Elements{
					podName: MatchFields(IgnoreExtras, Fields{

						"ObjectMeta": MatchFields(IgnoreExtras, Fields{
							"Labels": MatchAllKeys(Keys{
								kube.LabelResourceKind:      Equal("Pod"),
								kube.LabelResourceName:      Equal(podName),
								kube.LabelResourceNamespace: Equal(podNamespace),
							}),
							"OwnerReferences": ConsistOf(metav1.OwnerReference{
								APIVersion: "v1",
								Kind:       "Pod",
								Name:       podName,
								UID:        pod.UID,
							}),
						}),
						"Report": MatchFields(IgnoreExtras, Fields{
							"Scanner": Equal(v1alpha1.Scanner{
								Name:    "Polaris",
								Vendor:  "Fairwinds Ops",
								Version: "1.2",
							}),
						}),
					}),
				}))
			})

			AfterEach(func() {
				err := kubernetesClientset.CoreV1().Pods(podNamespace).
					Delete(context.TODO(), podName, metav1.DeleteOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

		})

	})

	Describe("Command run kube-bench", func() {

		It("should run kube-bench", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"kube-bench",
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
							APIVersion: "v1",
							Kind:       "Node",
							Name:       node.Name,
							UID:        node.UID,
						}),
					}),
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
	})

})
