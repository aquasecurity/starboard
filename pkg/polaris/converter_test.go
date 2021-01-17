package polaris_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/polaris"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
)

func TestConverter_Convert(t *testing.T) {
	file, err := os.Open("testdata/polaris-report.json")
	require.NoError(t, err)
	defer func() {
		_ = file.Close()
	}()

	want := v1alpha1.ConfigAuditResult{
		Scanner: v1alpha1.Scanner{
			Name:    "Polaris",
			Vendor:  "Fairwinds Ops",
			Version: "latest",
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
		Summary: v1alpha1.ConfigAuditSummary{
			PassCount: 4,
		},
	}

	got, err := polaris.NewConverter(starboard.ConfigData{
		"polaris.imageRef": "latest",
	}).Convert(file)
	require.NoError(t, err)

	if diff := cmp.Diff(want, got,
		cmpopts.IgnoreFields(v1alpha1.ConfigAuditResult{}, "UpdateTimestamp"),
		cmpopts.SortSlices(func(a, b v1alpha1.Check) bool {
			return a.ID < b.ID
		})); diff != "" {
		t.Errorf("diff (-want, +got): %v\n", diff)
	}
}
