package starboard_operator

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/starboard/itest/helper"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
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

		var ctx context.Context
		var pod *corev1.Pod

		BeforeEach(func() {
			ctx = context.Background()
			pod = helper.NewPod().
				WithName("unmanaged-nginx").
				WithNamespace(corev1.NamespaceDefault).
				WithContainer("nginx", "nginx:1.16").
				Build()

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

		var ctx context.Context
		var deploy *appsv1.Deployment

		BeforeEach(func() {
			ctx = context.Background()
			deploy = helper.NewDeployment().
				WithName(baseDeploymentName+"-"+rand.String(5)).
				WithNamespace(namespaceName).
				WithContainer("wordpress", "wordpress:4.9").
				Build()

			err := kubeClient.Create(ctx, deploy)
			Expect(err).ToNot(HaveOccurred())
			Eventually(HasActiveReplicaSet(namespaceName, deploy.Name), assertionTimeout).Should(BeTrue())
		})

		It("Should create VulnerabilityReport and ConfigAuditReport", func() {
			rs, err := GetActiveReplicaSetForDeployment(namespaceName, deploy.Name)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			Eventually(HasConfigAuditReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
			Eventually(HasVulnerabilityReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClient.Delete(ctx, deploy)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("When Deployment is rolling updated", func() {

		var ctx context.Context
		var deploy *appsv1.Deployment

		BeforeEach(func() {
			By("Creating Deployment wordpress")
			ctx = context.Background()
			deploy = helper.NewDeployment().
				WithName(baseDeploymentName+"-"+rand.String(5)).
				WithNamespace(namespaceName).
				WithContainer("wordpress", "wordpress:4.9").
				Build()

			err := kubeClient.Create(ctx, deploy)
			Expect(err).ToNot(HaveOccurred())
			Eventually(HasActiveReplicaSet(namespaceName, deploy.Name), assertionTimeout).Should(BeTrue())
		})

		It("Should create VulnerabilityReport and ConfigAuditReport for new ReplicaSet", func() {
			By("Getting current active ReplicaSet")
			rs, err := GetActiveReplicaSetForDeployment(namespaceName, deploy.Name)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			By("Waiting for ConfigAuditReport")
			Eventually(HasConfigAuditReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
			By("Waiting for VulnerabilityReport")
			Eventually(HasVulnerabilityReportOwnedBy(rs), assertionTimeout).Should(BeTrue())

			By("Updating deployment image to wordpress:5")
			err = UpdateDeploymentImage(namespaceName, deploy.Name) // TODO Helper
			Expect(err).ToNot(HaveOccurred())

			Eventually(HasActiveReplicaSet(namespaceName, deploy.Name), assertionTimeout).Should(BeTrue())

			By("Getting new active replicaset")
			rs, err = GetActiveReplicaSetForDeployment(namespaceName, deploy.Name)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			By("Waiting for new Config Audit Report")
			Eventually(HasConfigAuditReportOwnedBy(rs), assertionTimeout).Should(BeTrue())

			By("Waiting for new Vulnerability Report")
			Eventually(HasVulnerabilityReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClient.Delete(ctx, deploy)
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
			Eventually(HasVulnerabilityReportOwnedBy(cronJob), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClient.Delete(context.Background(), cronJob)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("When operator is started", func() {

		It("Should create CISKubeBenchReports", func() {
			var nodeList corev1.NodeList
			err := kubeClient.List(context.Background(), &nodeList)
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
	var deployment appsv1.Deployment
	var replicaSetList appsv1.ReplicaSetList

	err := kubeClient.Get(context.TODO(), types.NamespacedName{
		Name: name, Namespace: namespace,
	}, &deployment)
	if err != nil {
		return nil, err
	}

	deploymentSelector, err := metav1.LabelSelectorAsMap(deployment.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("mapping label selector: %w", err)
	}
	selector := labels.Set(deploymentSelector)

	err = kubeClient.List(context.TODO(), &replicaSetList, client.MatchingLabels(selector))

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
	// TODO Check kubectl set image implementation
	return wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		var deployment appsv1.Deployment
		err := kubeClient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, &deployment)
		if err != nil {
			return false, err
		}

		dcDeploy := deployment.DeepCopy()
		dcDeploy.Spec.Template.Spec.Containers[0].Image = "wordpress:5"
		err = kubeClient.Update(context.TODO(), dcDeploy)
		if err != nil && errors.IsConflict(err) {
			return false, nil
		}

		return err == nil, err
	})
}
