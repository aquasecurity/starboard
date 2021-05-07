package helper

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/starboard"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

type PodBuilder struct {
	name             string
	namespace        string
	containers       []corev1.Container
	imagePullSecrets []corev1.LocalObjectReference
}

func NewPod() *PodBuilder {
	return &PodBuilder{}
}

func (b *PodBuilder) WithName(name string) *PodBuilder {
	b.name = name
	return b
}

func (b *PodBuilder) WithRandomName(prefix string) *PodBuilder {
	return b.WithName(prefix + "-" + rand.String(5))
}

func (b *PodBuilder) WithNamespace(namespace string) *PodBuilder {
	b.namespace = namespace
	return b
}

func (b *PodBuilder) WithContainer(name, image string) *PodBuilder {
	b.containers = append(b.containers, corev1.Container{
		Name:  name,
		Image: image,
	})
	return b
}

func (b *PodBuilder) WithImagePullSecret(name string) *PodBuilder {
	b.imagePullSecrets = append(b.imagePullSecrets, corev1.LocalObjectReference{
		Name: name,
	})
	return b
}

func (b *PodBuilder) Build() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
		},
		Spec: corev1.PodSpec{
			Containers:       b.containers,
			ImagePullSecrets: b.imagePullSecrets,
		},
	}
}

type DeploymentBuilder struct {
	name       string
	namespace  string
	containers []corev1.Container
}

func NewDeployment() *DeploymentBuilder {
	return &DeploymentBuilder{}
}

func (b *DeploymentBuilder) WithName(name string) *DeploymentBuilder {
	b.name = name
	return b
}

func (b *DeploymentBuilder) WithRandomName(prefix string) *DeploymentBuilder {
	return b.WithName(prefix + "-" + rand.String(5))
}

func (b *DeploymentBuilder) WithNamespace(namespace string) *DeploymentBuilder {
	b.namespace = namespace
	return b
}

func (b *DeploymentBuilder) WithContainer(name, image string) *DeploymentBuilder {
	b.containers = append(b.containers, corev1.Container{
		Name:  name,
		Image: image,
	})
	return b
}

func (b *DeploymentBuilder) Build() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: pointer.Int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": b.name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels.Set{
						"app": b.name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: b.containers,
				},
			},
		},
	}
}

var (
	trivyScanner = v1alpha1.Scanner{
		Name:    "Trivy",
		Vendor:  "Aqua Security",
		Version: "0.16.0",
	}
)

type VulnerabilityReportBuilder struct {
	name      string
	namespace string
	ownerKind kube.Kind
	ownerName string
}

func NewVulnerabilityReport() *VulnerabilityReportBuilder {
	return &VulnerabilityReportBuilder{}
}

func (b *VulnerabilityReportBuilder) WithName(name string) *VulnerabilityReportBuilder {
	b.name = name
	return b
}

func (b *VulnerabilityReportBuilder) WithNamespace(namespace string) *VulnerabilityReportBuilder {
	b.namespace = namespace
	return b
}

func (b *VulnerabilityReportBuilder) WithOwnerKind(kind kube.Kind) *VulnerabilityReportBuilder {
	b.ownerKind = kind
	return b
}

func (b *VulnerabilityReportBuilder) WithOwnerName(name string) *VulnerabilityReportBuilder {
	b.ownerName = name
	return b
}

func (b *VulnerabilityReportBuilder) Build() *v1alpha1.VulnerabilityReport {
	return &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
			Labels: map[string]string{
				starboard.LabelContainerName:     "nginx", // TODO Make it configurable
				starboard.LabelResourceKind:      string(b.ownerKind),
				starboard.LabelResourceName:      b.ownerName,
				starboard.LabelResourceNamespace: b.namespace,
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

// Helper is a mix of asserts and helpers, but we can fix that later.
type Helper struct {
	scheme                *runtime.Scheme
	kubeClient            client.Client
	kubeBenchReportReader kubebench.Reader
}

func NewHelper(scheme *runtime.Scheme, client client.Client) *Helper {
	return &Helper{
		scheme:                scheme,
		kubeClient:            client,
		kubeBenchReportReader: kubebench.NewReadWriter(client),
	}
}

func (h *Helper) HasActiveReplicaSet(namespace, name string) func() (bool, error) {
	return func() (bool, error) {
		rs, err := h.GetActiveReplicaSetForDeployment(namespace, name)
		if err != nil {
			return false, err
		}
		return rs != nil, nil
	}
}

func (h *Helper) HasVulnerabilityReportOwnedBy(obj client.Object) func() (bool, error) {
	return func() (bool, error) {
		gvk, err := apiutil.GVKForObject(obj, h.scheme)
		if err != nil {
			return false, err
		}
		var reportList v1alpha1.VulnerabilityReportList
		err = h.kubeClient.List(context.Background(), &reportList, client.MatchingLabels{
			starboard.LabelResourceKind:      gvk.Kind,
			starboard.LabelResourceName:      obj.GetName(),
			starboard.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			return false, err
		}
		return len(reportList.Items) == 1, nil
	}
}

func (h *Helper) HasConfigAuditReportOwnedBy(obj client.Object) func() (bool, error) {
	return func() (bool, error) {
		gvk, err := apiutil.GVKForObject(obj, h.scheme)
		if err != nil {
			return false, err
		}
		var reportsList v1alpha1.ConfigAuditReportList
		err = h.kubeClient.List(context.Background(), &reportsList, client.MatchingLabels{
			starboard.LabelResourceKind:      gvk.Kind,
			starboard.LabelResourceName:      obj.GetName(),
			starboard.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			return false, err
		}

		return len(reportsList.Items) == 1 && reportsList.Items[0].DeletionTimestamp == nil, nil
	}
}

func (h *Helper) DeleteConfigAuditReportOwnedBy(obj client.Object) error {
	gvk, err := apiutil.GVKForObject(obj, h.scheme)
	if err != nil {
		return err
	}
	var reportsList v1alpha1.ConfigAuditReportList
	err = h.kubeClient.List(context.Background(), &reportsList, client.MatchingLabels{
		starboard.LabelResourceKind:      gvk.Kind,
		starboard.LabelResourceName:      obj.GetName(),
		starboard.LabelResourceNamespace: obj.GetNamespace(),
	})
	if err != nil {
		return err
	}

	return h.kubeClient.Delete(context.Background(), &reportsList.Items[0])
}

func (h *Helper) GetActiveReplicaSetForDeployment(namespace, name string) (*appsv1.ReplicaSet, error) {
	var deployment appsv1.Deployment
	var replicaSetList appsv1.ReplicaSetList

	err := h.kubeClient.Get(context.TODO(), types.NamespacedName{
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

	err = h.kubeClient.List(context.TODO(), &replicaSetList, client.MatchingLabels(selector))

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

func (h *Helper) HasCISKubeBenchReportOwnedBy(node corev1.Node) func() (bool, error) {
	return func() (bool, error) {
		report, err := h.kubeBenchReportReader.FindByOwner(context.Background(), kube.Object{Kind: kube.KindNode, Name: node.Name})
		if err != nil {
			return false, err
		}
		return report != nil, nil
	}
}

func (h *Helper) UpdateDeploymentImage(namespace, name string) error {
	// TODO Check kubectl set image implementation
	return wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		var deployment appsv1.Deployment
		err := h.kubeClient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, &deployment)
		if err != nil {
			return false, err
		}

		dcDeploy := deployment.DeepCopy()
		dcDeploy.Spec.Template.Spec.Containers[0].Image = "wordpress:5"
		err = h.kubeClient.Update(context.TODO(), dcDeploy)
		if err != nil && errors.IsConflict(err) {
			return false, nil
		}

		return err == nil, err
	})
}
