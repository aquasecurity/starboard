package aqua

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/ext"

	"github.com/aquasecurity/starboard/pkg/starboard"
	"k8s.io/apimachinery/pkg/api/resource"

	aquasecurityv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/operator/scanner"

	"github.com/aquasecurity/starboard/pkg/operator/etc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"
)

const (
	secretName = "starboard-operator"
)

type aquaScanner struct {
	idGenerator ext.IDGenerator
	buildInfo   starboard.BuildInfo
	config      etc.ScannerAquaCSP
}

// NewScanner constructs a new VulnerabilityScanner, which is using the Aqua scanner
// to scan pod containers.
func NewScanner(idGenerator ext.IDGenerator, buildInfo starboard.BuildInfo, config etc.ScannerAquaCSP) scanner.VulnerabilityScanner {
	return &aquaScanner{
		idGenerator: idGenerator,
		buildInfo:   buildInfo,
		config:      config,
	}
}

func (s *aquaScanner) GetPodTemplateSpec(spec corev1.PodSpec, options scanner.Options) (corev1.PodTemplateSpec, error) {
	initContainerName := s.idGenerator.GenerateID()

	scanJobContainers := make([]corev1.Container, len(spec.Containers))
	for i, container := range spec.Containers {
		var err error
		scanJobContainers[i], err = s.newScanJobContainer(container)
		if err != nil {
			return corev1.PodTemplateSpec{}, err
		}
	}

	return corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			ServiceAccountName:           options.ServiceAccountName,
			AutomountServiceAccountToken: pointer.BoolPtr(false),
			NodeName:                     spec.NodeName,
			Volumes: []corev1.Volume{
				{
					Name: "scannercli",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "dockersock",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/docker.sock",
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Name:  initContainerName,
					Image: s.config.ImageRef,
					Command: []string{
						"cp",
						"/opt/aquasec/scannercli",
						"/downloads/scannercli",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "scannercli",
							MountPath: "/downloads",
						},
					},
				},
			},
			Containers: scanJobContainers,
		},
	}, nil
}

func (s *aquaScanner) newScanJobContainer(podContainer corev1.Container) (corev1.Container, error) {
	version, err := starboard.GetVersionFromImageRef(s.config.ImageRef)
	if err != nil {
		return corev1.Container{}, err
	}

	return corev1.Container{
		Name:            podContainer.Name,
		Image:           fmt.Sprintf("aquasec/starboard-scanner-aqua:%s", s.buildInfo.Version),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{
			"/bin/sh",
			"-c",
			fmt.Sprintf("/usr/local/bin/starboard-scanner-aqua --version $(AQUA_VERSION) --host $(AQUA_CSP_HOST) --user $(AQUA_CSP_USERNAME) --password $(AQUA_CSP_PASSWORD) %s 2> %s",
				podContainer.Image,
				corev1.TerminationMessagePathDefault),
		},
		Env: []corev1.EnvVar{
			{
				Name:  "AQUA_VERSION",
				Value: version,
			},
			{
				Name: "AQUA_CSP_HOST",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_HOST",
					},
				},
			},
			{
				Name: "AQUA_CSP_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_USERNAME",
					},
				},
			},
			{
				Name: "AQUA_CSP_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_PASSWORD",
					},
				},
			},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("100M"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500M"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "scannercli",
				MountPath: "/usr/local/bin/scannercli",
				SubPath:   "scannercli",
			},
			{
				Name:      "dockersock",
				MountPath: "/var/run/docker.sock",
			},
		},
	}, nil
}

func (s *aquaScanner) ParseVulnerabilityScanResult(_ string, logsReader io.ReadCloser) (aquasecurityv1alpha1.VulnerabilityScanResult, error) {
	var report aquasecurityv1alpha1.VulnerabilityScanResult
	err := json.NewDecoder(logsReader).Decode(&report)
	return report, err
}
