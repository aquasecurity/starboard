package polaris

import (
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/starboard/pkg/ext"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_Convert(t *testing.T) {
	file, err := os.Open("test_fixture/polaris-report.json")
	require.NoError(t, err)
	defer func() {
		_ = file.Close()
	}()
	now := time.Now()

	reports, err := NewConverter(ext.NewFixedClock(now)).Convert(file)
	require.NoError(t, err)
	assert.Equal(t, []v1alpha1.ConfigAudit{
		{
			GeneratedAt: meta.NewTime(now),
			Scanner: v1alpha1.Scanner{
				Name:    "Polaris",
				Vendor:  "Fairwinds",
				Version: "latest",
			},
			Resource: v1alpha1.KubernetesNamespacedResource{
				Namespace: "aqua",
				KubernetesResource: v1alpha1.KubernetesResource{
					Kind: "Deployment",
					Name: "csp-database",
				},
			},
			PodChecks: []v1alpha1.Check{
				{
					ID:       "hostIPCSet",
					Message:  "Host IPC is not configured",
					Success:  true,
					Severity: "error",
					Category: "Security",
				},
				{
					ID:       "hostNetworkSet",
					Message:  "Host network is not configured",
					Success:  true,
					Severity: "warning",
					Category: "Networking",
				},
			},
			ContainerChecks: map[string][]v1alpha1.Check{
				"db": {
					{
						ID:       "cpuLimitsMissing",
						Message:  "CPU limits are set",
						Success:  true,
						Severity: "warning",
						Category: "Resources",
					},
					{
						ID:       "cpuRequestsMissing",
						Message:  "CPU requests are set",
						Success:  true,
						Severity: "warning",
						Category: "Resources",
					},
				},
			},
		},
	}, reports)
}
