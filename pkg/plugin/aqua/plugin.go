package aqua

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/docker"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/pointer"
)

type plugin struct {
	idGenerator ext.IDGenerator
	buildInfo   starboard.BuildInfo
}

// NewPlugin constructs a new vulnerabilityreport.Plugin, which is using
// the Aqua Enterprise to scan container images of Kubernetes workloads.
func NewPlugin(
	idGenerator ext.IDGenerator,
	buildInfo starboard.BuildInfo,
) vulnerabilityreport.Plugin {
	return &plugin{
		idGenerator: idGenerator,
		buildInfo:   buildInfo,
	}
}

func (s *plugin) GetScanJobSpec(ctx starboard.PluginContext, spec corev1.PodSpec, _ map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	initContainerName := s.idGenerator.GenerateID()

	aquaImageRef, err := s.getImageRef(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	scanJobContainers := make([]corev1.Container, len(spec.Containers))
	for i, container := range spec.Containers {
		var err error
		scanJobContainers[i], err = s.newScanJobContainer(ctx, container)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
	}

	return corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
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
				Image: aquaImageRef,
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
	}, nil, nil
}

func (s *plugin) newScanJobContainer(ctx starboard.PluginContext, podContainer corev1.Container) (corev1.Container, error) {
	aquaImageRef, err := s.getImageRef(ctx)
	if err != nil {
		return corev1.Container{}, err
	}
	version, err := starboard.GetVersionFromImageRef(aquaImageRef)
	if err != nil {
		return corev1.Container{}, err
	}

	return corev1.Container{
		Name:                     podContainer.Name,
		Image:                    fmt.Sprintf("aquasec/starboard-scanner-aqua:%s", s.buildInfo.Version),
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
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
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.GetPluginConfigMapName("Aqua"),
						},
						Key: "aqua.serverURL",
					},
				},
			},
			{
				Name: "AQUA_CSP_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.GetPluginConfigMapName("Aqua"),
						},
						Key: "aqua.username",
					},
				},
			},
			{
				Name: "AQUA_CSP_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: starboard.GetPluginConfigMapName("Aqua"),
						},
						Key: "aqua.password",
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

func (s *plugin) ParseVulnerabilityReportData(_ string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error) {
	var report v1alpha1.VulnerabilityScanResult
	err := json.NewDecoder(logsReader).Decode(&report)
	return report, err
}

func (s *plugin) getImageRef(ctx starboard.PluginContext) (string, error) {
	config, err := ctx.GetConfig()
	if err != nil {
		return "", err
	}
	return config.GetRequiredData("aqua.imageRef")
}
