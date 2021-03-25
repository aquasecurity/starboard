package starboard_operator

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

const (
	assertionTimeout   = 3 * time.Minute
	namespaceName      = corev1.NamespaceDefault
	baseDeploymentName = "wordpress"
)

var _ = Describe("Starboard Operator", func() {

	Describe("When unmanaged Pod is created", func() {

		ctx := context.Background()
		var pod *corev1.Pod

		BeforeEach(func() {
			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unmanaged-nginx",
					Namespace: corev1.NamespaceDefault,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			}
			err := kubeClient.Create(ctx, pod)
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should create VulnerabilityReport and ConfigAuditReport", func() {
			Eventually(HasConfigAuditReportOwnedBy(pod), assertionTimeout).Should(BeTrue())
			Eventually(HasVulnerabilityReportOwnedBy(pod), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClient.Delete(ctx, pod)
			Expect(err).ToNot(HaveOccurred())
		})

	})

	Describe("When Deployment is created", func() {

		ctx := context.Background()
		deploy := GetWordPressDeployment()
		deploymentName := deploy.Name

		BeforeEach(func() {
			_, err := kubeClientset.AppsV1().Deployments(namespaceName).
				Create(ctx, deploy, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			Eventually(HasActiveReplicaSet(namespaceName, deploymentName), assertionTimeout).Should(BeTrue())
		})

		It("Should create VulnerabilityReport and ConfigAuditReport", func() {
			rs, err := GetActiveReplicaSetForDeployment(namespaceName, deploymentName)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			Eventually(HasConfigAuditReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
			Eventually(HasVulnerabilityReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClientset.AppsV1().Deployments(namespaceName).
				Delete(ctx, deploymentName, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("When Deployment is rolling updated", func() {

		ctx := context.Background()
		deploy := GetWordPressDeployment()
		deploymentName := deploy.Name

		BeforeEach(func() {
			By("Creating Deployment wordpress")
			_, err := kubeClientset.AppsV1().Deployments(namespaceName).
				Create(ctx, deploy, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			Eventually(HasActiveReplicaSet(namespaceName, deploymentName), assertionTimeout).Should(BeTrue())
		})

		It("Should create VulnerabilityReport and ConfigAuditReport for new Replicaset", func() {
			By("Getting current active replicaset")
			rs, err := GetActiveReplicaSetForDeployment(namespaceName, deploymentName)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			By("Waiting for Config Audit Report")
			Eventually(HasConfigAuditReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
			By("Waiting for Vulnerability Report")
			Eventually(HasVulnerabilityReportOwnedBy(rs), assertionTimeout).Should(BeTrue())

			By("Updating deployment image to wordpress:5")
			err = UpdateDeploymentImage(namespaceName, deploymentName)
			Expect(err).ToNot(HaveOccurred())

			Eventually(HasActiveReplicaSet(namespaceName, deploymentName), assertionTimeout).Should(BeTrue())

			By("Getting new active replicaset")
			rs, err = GetActiveReplicaSetForDeployment(namespaceName, deploymentName)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			By("Waiting for new Config Audit Report")
			Eventually(HasConfigAuditReportOwnedBy(rs), assertionTimeout).Should(BeTrue())

			By("Waiting for new Vulnerability Report")
			Eventually(HasVulnerabilityReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClientset.AppsV1().Deployments(namespaceName).
				Delete(ctx, deploymentName, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("When CronJob is created", func() {
		var cronJob *batchv1beta1.CronJob

		BeforeEach(func() {
			cronJob = &batchv1beta1.CronJob{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespaceName,
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

		It("Should create VulnerabilityReport and ConfigAuditReport", func() {
			Eventually(HasConfigAuditReportOwnedBy(cronJob), assertionTimeout).Should(BeTrue())
			// FIXME(issue: #415): Assign VulnerabilityReports to CronJob instead of Jobs. The PodSpec of a CronJob does not change so there's no point in rescanning individual Jobs.
			// Eventually(HasVulnerabilityReportOwnedBy(cronJob), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClient.Delete(context.Background(), cronJob)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("When operator is started", func() {

		It("Should scan all nodes with CIS Kubernetes Benchmark checks", func() {
			nodeList, err := kubeClientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			Expect(err).ToNot(HaveOccurred())
			for _, node := range nodeList.Items {
				Eventually(HasCISKubeBenchReportOwnedBy(node), assertionTimeout).Should(BeTrue())
			}
		})

	})
})

func HasActiveReplicaSet(namespace, name string) func() (bool, error) {
	return func() (bool, error) {
		rs, err := GetActiveReplicaSetForDeployment(namespace, name)
		if err != nil {
			return false, err
		}
		return rs != nil, nil
	}
}

func HasVulnerabilityReportOwnedBy(obj client.Object) func() (bool, error) {
	return func() (bool, error) {
		gvk, err := apiutil.GVKForObject(obj, scheme)
		if err != nil {
			return false, err
		}
		var reportList v1alpha1.VulnerabilityReportList
		err = kubeClient.List(context.Background(), &reportList, client.MatchingLabels{
			kube.LabelResourceKind:      gvk.Kind,
			kube.LabelResourceName:      obj.GetName(),
			kube.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			return false, err
		}
		return len(reportList.Items) == 1, nil
	}
}

func HasConfigAuditReportOwnedBy(obj client.Object) func() (bool, error) {
	return func() (bool, error) {
		gvk, err := apiutil.GVKForObject(obj, scheme)
		if err != nil {
			return false, err
		}
		var reportsList v1alpha1.ConfigAuditReportList
		err = kubeClient.List(context.Background(), &reportsList, client.MatchingLabels{
			kube.LabelResourceKind:      gvk.Kind,
			kube.LabelResourceName:      obj.GetName(),
			kube.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			return false, err
		}
		return len(reportsList.Items) == 1, nil
	}
}

func GetActiveReplicaSetForDeployment(namespace, name string) (*appsv1.ReplicaSet, error) {
	deployment, err := kubeClientset.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	deploymentSelector, err := metav1.LabelSelectorAsMap(deployment.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("mapping label selector: %w", err)
	}
	selector := labels.Set(deploymentSelector)

	replicaSetList, err := kubeClientset.AppsV1().ReplicaSets(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, err
	}

	for _, replicaSet := range replicaSetList.Items {
		if deployment.Annotations["deployment.kubernetes.io/revision"] !=
			replicaSet.Annotations["deployment.kubernetes.io/revision"] {
			continue
		}
		return replicaSet.DeepCopy(), nil
	}
	return nil, nil
}

func HasCISKubeBenchReportOwnedBy(node corev1.Node) func() (bool, error) {
	return func() (bool, error) {
		report, err := kubeBenchReportReader.FindByOwner(context.Background(), kube.Object{Kind: kube.KindNode, Name: node.Name})
		if err != nil {
			return false, err
		}
		return report != nil, nil
	}
}

func UpdateDeploymentImage(namespace, name string) error {
	return wait.PollImmediate(5*time.Second, 2*time.Minute, func() (done bool, err error) {
		deployment, err := kubeClientset.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		dcDeploy := deployment.DeepCopy()
		dcDeploy.Spec.Template.Spec.Containers[0].Image = "wordpress:5"
		_, err = kubeClientset.AppsV1().Deployments(namespace).Update(context.TODO(), dcDeploy, metav1.UpdateOptions{})
		if err != nil && errors.IsConflict(err) {
			return false, nil
		}

		return err == nil, err
	})
}

func GetWordPressDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseDeploymentName + "-" + rand.String(5),
			Namespace: namespaceName,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: pointer.Int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "wordpress",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels.Set{
						"app": "wordpress",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "wordpress",
							Image: "wordpress:4.9",
						},
					},
				},
			},
		},
	}
}
