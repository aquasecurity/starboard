package conftest_test

import (
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"context"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/plugin/conftest"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

func TestPlugin_Init(t *testing.T) {
	g := NewGomegaWithT(t)

	client := fake.NewClientBuilder().WithObjects().Build()

	instance := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)

	pluginContext := starboard.NewPluginContext().
		WithName(string(starboard.Conftest)).
		WithNamespace("starboard-ns").
		WithServiceAccountName("starboard-sa").
		WithClient(client).
		Get()
	err := instance.Init(pluginContext)
	g.Expect(err).ToNot(HaveOccurred())

	var cm corev1.ConfigMap
	err = client.Get(context.Background(), types.NamespacedName{
		Namespace: "starboard-ns",
		Name:      "starboard-conftest-config",
	}, &cm)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cm).To(Equal(corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "starboard-conftest-config",
			Namespace: "starboard-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "starboard",
			},
			ResourceVersion: "1",
		},
		Data: map[string]string{
			"conftest.imageRef": "openpolicyagent/conftest:v0.25.0",
		},
	}))
}

func TestPlugin_GetScanJobSpec(t *testing.T) {
	g := NewGomegaWithT(t)
	sequence := ext.NewSimpleIDGenerator()
	pluginContext := starboard.NewPluginContext().
		WithName(string(starboard.Conftest)).
		WithNamespace("starboard-ns").
		WithServiceAccountName("starboard-sa").
		WithClient(fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "starboard-conftest-config",
				Namespace: "starboard-ns",
			},
			Data: map[string]string{
				"conftest.imageRef": "openpolicyagent/conftest:v0.23.0",

				"conftest.policy.libkubernetes.rego":      "<REGO>",
				"conftest.policy.libutil.rego":            "<REGO>",
				"conftest.policy.access_to_host_pid.rego": "<REGO>",
				"conftest.policy.cpu_not_limited.rego":    "<REGO>",
				"conftest.policy.privileged":              "<REGO>", // This one should be skipped (no .rego suffix)

				"foo": "bar", // This one should be skipped (no conftest.policy. prefix)
			},
		}).Build()).Get()

	instance := conftest.NewPlugin(sequence, fixedClock)

	jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.16",
				},
			},
		},
	})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(jobSpec).To(MatchFields(IgnoreExtras, Fields{
		"ServiceAccountName":           Equal("starboard-sa"),
		"AutomountServiceAccountToken": PointTo(BeFalse()),
		"RestartPolicy":                Equal(corev1.RestartPolicyNever),
		"Affinity":                     Equal(starboard.LinuxNodeAffinity()),
		"Volumes": ConsistOf(
			MatchFields(IgnoreExtras, Fields{
				"Name": Equal("scan-configauditreport-5d4445db4f-volume"),
				// We cannot inline assert here on other properties with the MatchFields matcher
				// because the value of the Secret field is the pointer to v1.SecretVolumeSource.
				// The MatchFields matcher only works with structs :-(
			}),
		),
		"Containers": ContainElements(
			MatchFields(IgnoreExtras, Fields{
				"Name":                     Equal("conftest"),
				"Image":                    Equal("openpolicyagent/conftest:v0.23.0"),
				"ImagePullPolicy":          Equal(corev1.PullIfNotPresent),
				"TerminationMessagePolicy": Equal(corev1.TerminationMessageFallbackToLogsOnError),
				"Resources": Equal(corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("300m"),
						corev1.ResourceMemory: resource.MustParse("300M"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("50M"),
					},
				}),
				"VolumeMounts": ConsistOf(
					corev1.VolumeMount{
						Name:      "scan-configauditreport-5d4445db4f-volume",
						MountPath: "/project/policy/libkubernetes.rego",
						SubPath:   "libkubernetes.rego",
						ReadOnly:  true,
					},
					corev1.VolumeMount{
						Name:      "scan-configauditreport-5d4445db4f-volume",
						MountPath: "/project/policy/libutil.rego",
						SubPath:   "libutil.rego",
						ReadOnly:  true,
					},
					corev1.VolumeMount{
						Name:      "scan-configauditreport-5d4445db4f-volume",
						MountPath: "/project/policy/access_to_host_pid.rego",
						SubPath:   "access_to_host_pid.rego",
						ReadOnly:  true,
					},
					corev1.VolumeMount{
						Name:      "scan-configauditreport-5d4445db4f-volume",
						MountPath: "/project/policy/cpu_not_limited.rego",
						SubPath:   "cpu_not_limited.rego",
						ReadOnly:  true,
					},
					corev1.VolumeMount{
						Name:      "scan-configauditreport-5d4445db4f-volume",
						MountPath: "/project/workload.yaml",
						SubPath:   "workload.yaml",
						ReadOnly:  true,
					},
				),
				"Command": Equal([]string{
					"sh",
				}),
				"Args": Equal([]string{
					"-c",
					"conftest test --no-fail --output json --all-namespaces --policy /project/policy /project/workload.yaml",
				}),
				"SecurityContext": Equal(&corev1.SecurityContext{
					Privileged:               pointer.BoolPtr(false),
					AllowPrivilegeEscalation: pointer.BoolPtr(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"all"},
					},
					ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				}),
			}),
		),
		"SecurityContext": Equal(&corev1.PodSecurityContext{}),
	}))
	g.Expect(*jobSpec.Volumes[0].VolumeSource.Secret).To(MatchFields(IgnoreExtras, Fields{
		"SecretName": Equal("scan-configauditreport-5d4445db4f-volume"),
		"Items": ConsistOf(
			corev1.KeyToPath{
				Key:  "conftest.policy.libkubernetes.rego",
				Path: "libkubernetes.rego",
			},
			corev1.KeyToPath{
				Key:  "conftest.policy.libutil.rego",
				Path: "libutil.rego",
			},
			corev1.KeyToPath{
				Key:  "conftest.policy.access_to_host_pid.rego",
				Path: "access_to_host_pid.rego",
			},
			corev1.KeyToPath{
				Key:  "conftest.policy.cpu_not_limited.rego",
				Path: "cpu_not_limited.rego",
			},
			corev1.KeyToPath{
				Key:  "starboard.workload.yaml",
				Path: "workload.yaml",
			},
		),
	}))
	g.Expect(secrets).To(ConsistOf(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scan-configauditreport-5d4445db4f-volume",
				Namespace: "starboard-ns",
			},
			StringData: map[string]string{
				"conftest.policy.libkubernetes.rego":      "<REGO>",
				"conftest.policy.libutil.rego":            "<REGO>",
				"conftest.policy.access_to_host_pid.rego": "<REGO>",
				"conftest.policy.cpu_not_limited.rego":    "<REGO>",
				"starboard.workload.yaml": `metadata:
  creationTimestamp: null
  name: nginx
  namespace: default
spec:
  containers:
  - image: nginx:1.16
    name: nginx
    resources: {}
status: {}
`,
			},
		},
	))
}

func TestPlugin_ParseConfigAuditReportData(t *testing.T) {
	g := NewGomegaWithT(t)
	plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
	logsReader := ioutil.NopCloser(strings.NewReader(`[
  {
    "filename": "/project/workload.yaml",
    "namespace": "appshield.KSV003",
    "successes": -3,
    "failures": [
      {
        "msg": "container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
        "metadata": {
          "title": "Default capabilities: some containers do not drop all"
        }
      },
      {
        "msg": "container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
        "metadata": {
          "title": "Default capabilities: some containers do not drop all"
        }
      },
      {
        "msg": "container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
        "metadata": {
          "title": "Default capabilities: some containers do not drop all"
        }
      },
      {
        "msg": "container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
        "metadata": {
          "title": "Default capabilities: some containers do not drop all"
        }
      }
    ]
  },
  {
    "filename": "/project/workload.yaml",
    "namespace": "appshield.KSV014",
    "successes": 0,
    "failures": [
      {
        "msg": "container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true",
        "metadata": {
          "title": "Root file system is not read-only"
        }
      }
    ]
  },
  {
    "filename": "/project/workload.yaml",
    "namespace": "appshield.KSV025",
    "successes": 1
  },
  {
    "filename": "/project/workload.yaml",
    "namespace": "appshield.KSV017",
    "successes": 1
  },
  {
    "filename": "/project/workload.yaml",
    "namespace": "appshield.KSV015",
    "successes": 0,
    "failures": [
      {
        "msg": "container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu"
      }
    ]
  }
]`))

	pluginContext := starboard.NewPluginContext().
		WithName(string(starboard.Conftest)).
		WithNamespace("starboard-ns").
		WithServiceAccountName("starboard-sa").
		WithClient(fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "starboard-conftest-config",
				Namespace: "starboard-ns",
			},
			Data: map[string]string{
				"conftest.imageRef": "openpolicyagent/conftest:v0.25.0",
			},
		}).Build()).
		Get()

	data, err := plugin.ParseConfigAuditReportData(pluginContext, logsReader)

	// When Conftest plugin is used with https://github.com/aquasecurity/appshield
	// Rego scripts the Check.ID is not unique. For example, for a Pod with multiple
	// containers the Check.ID will be duplicated for each container, but the
	// Check.Message will be different.
	groupChecksByMessage := func(element interface{}) string {
		return element.(v1alpha1.Check).Message
	}

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(data).To(MatchFields(IgnoreExtras, Fields{
		"UpdateTimestamp": Equal(metav1.NewTime(fixedTime)),
		"Scanner": Equal(v1alpha1.Scanner{
			Name:    "Conftest",
			Vendor:  "Open Policy Agent",
			Version: "v0.25.0",
		}),
		"Summary": Equal(v1alpha1.ConfigAuditSummary{
			DangerCount:  6,
			WarningCount: 0,
			PassCount:    2,
		}),
		"Checks": MatchAllElements(groupChecksByMessage, Elements{
			"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
				ID:       "Default capabilities: some containers do not drop all",
				Message:  "container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
				ID:       "Default capabilities: some containers do not drop all",
				Message:  "container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
				ID:       "Default capabilities: some containers do not drop all",
				Message:  "container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
				ID:       "Default capabilities: some containers do not drop all",
				Message:  "container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true": Equal(v1alpha1.Check{
				ID:       "Root file system is not read-only",
				Message:  "container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu": Equal(v1alpha1.Check{
				// If the author of a Rego script does not provide the title property
				// in the rule's response, which is then returned as metadata.type
				// in Conftest output, the parser will fallback to a unique identifier.
				ID:       "00000000-0000-0000-0000-000000000001",
				Message:  "container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
		}),
		// Most Rego scripts do not return structured response object to indicate
		// container name. Therefore, the ContainerChecks map is empty.
		"ContainerChecks": Equal(map[string][]v1alpha1.Check{}),
		"PodChecks": MatchAllElements(groupChecksByMessage, Elements{
			"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
				ID:       "Default capabilities: some containers do not drop all",
				Message:  "container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
				ID:       "Default capabilities: some containers do not drop all",
				Message:  "container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
				ID:       "Default capabilities: some containers do not drop all",
				Message:  "container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
				ID:       "Default capabilities: some containers do not drop all",
				Message:  "container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true": Equal(v1alpha1.Check{
				ID:       "Root file system is not read-only",
				Message:  "container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
			"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu": Equal(v1alpha1.Check{
				// If the author of a Rego script does not provide the title property
				// in the rule's response, which is then returned as metadata.type
				// in Conftest output, the parser will fallback to a unique identifier.
				ID:       "00000000-0000-0000-0000-000000000001",
				Message:  "container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu",
				Success:  false,
				Severity: "danger",
				Category: "Security",
			}),
		}),
	}))
}

func TestPlugin_GetConfigHash(t *testing.T) {

	newPluginContextWithConfigData := func(data map[string]string) starboard.PluginContext {
		return starboard.NewPluginContext().
			WithName("Conftest").
			WithNamespace("starboard-ns").
			WithClient(fake.NewClientBuilder().
				WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "starboard-conftest-config",
						Namespace: "starboard-ns",
					},
					Data: data,
				}).
				Build()).
			Get()
	}

	t.Run("Should return different hash for different config data", func(t *testing.T) {
		g := NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":   "bar",
			"brown": "fox",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"brown": "fox",
			"foo":   "baz",
		})

		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
		hash1, err := plugin.GetConfigHash(pluginContext1)
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.GetConfigHash(pluginContext2)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).ToNot(Equal(hash2))
	})

	t.Run("Should return the same hash for the same config data", func(t *testing.T) {
		g := NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":   "bar",
			"brown": "fox",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"brown": "fox",
			"foo":   "bar",
		})

		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
		hash1, err := plugin.GetConfigHash(pluginContext1)
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.GetConfigHash(pluginContext2)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).To(Equal(hash2))
	})
}

func TestPlugin_GetContainerName(t *testing.T) {
	g := NewGomegaWithT(t)

	plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
	g.Expect(plugin.GetContainerName()).To(Equal("conftest"))
}
