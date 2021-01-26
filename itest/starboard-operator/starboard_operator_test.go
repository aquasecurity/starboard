package starboard_operator

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/starboard/pkg/kube"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
)

const (
	assertionTimeout = 3 * time.Minute
)

var _ = Describe("Starboard Operator", func() {

	const (
		namespaceName  = corev1.NamespaceDefault
		deploymentName = "wordpress"
	)

	Describe("When a new Deployment is created", func() {

		ctx := context.Background()

		BeforeEach(func() {
			_, err := kubeClientset.AppsV1().Deployments(namespaceName).
				Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      deploymentName,
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
				}, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			Eventually(HasActiveReplicaSet(namespaceName, deploymentName), assertionTimeout).Should(BeTrue())
		})

		It("Should create VulnerabilityReport", func() {
			rs, err := GetActiveReplicaSetForDeployment(namespaceName, deploymentName)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			Eventually(HasVulnerabilityReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
		})

		It("Should create ConfigAuditReport", func() {
			rs, err := GetActiveReplicaSetForDeployment(namespaceName, deploymentName)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			Eventually(HasConfigAuditReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClientset.AppsV1().Deployments(namespaceName).
				Delete(ctx, deploymentName, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	// TODO Add a scenario for rolling update, i.e. create Deployment and then update its container image.

})

func HasActiveReplicaSet(namespace, name string) func() bool {
	return func() bool {
		rs, err := GetActiveReplicaSetForDeployment(namespace, name)
		if err != nil {
			return false
		}
		return rs != nil
	}
}

func HasVulnerabilityReportOwnedBy(rs *appsv1.ReplicaSet) func() bool {
	return func() bool {
		list, err := starboardClientset.AquasecurityV1alpha1().VulnerabilityReports(rs.Namespace).
			List(context.Background(), metav1.ListOptions{
				LabelSelector: labels.Set{
					kube.LabelResourceKind:      "ReplicaSet",
					kube.LabelResourceName:      rs.Name,
					kube.LabelResourceNamespace: rs.Namespace,
				}.String(),
			})
		if err != nil {
			return false
		}
		return len(list.Items) == 1
	}
}

func HasConfigAuditReportOwnedBy(rs *appsv1.ReplicaSet) func() bool {
	return func() bool {
		list, err := starboardClientset.AquasecurityV1alpha1().ConfigAuditReports(rs.Namespace).
			List(context.Background(), metav1.ListOptions{
				LabelSelector: labels.Set{
					kube.LabelResourceKind:      "ReplicaSet",
					kube.LabelResourceName:      rs.Name,
					kube.LabelResourceNamespace: rs.Namespace,
				}.String(),
			})
		if err != nil {
			return false
		}
		return len(list.Items) == 1
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
