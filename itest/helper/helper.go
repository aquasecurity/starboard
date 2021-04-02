package helper

import (
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
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
				kube.LabelContainerName:     "nginx", // TODO Make it configurable
				kube.LabelResourceKind:      string(b.ownerKind),
				kube.LabelResourceName:      b.ownerName,
				kube.LabelResourceNamespace: b.namespace,
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
