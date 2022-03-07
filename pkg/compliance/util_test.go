package compliance

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"testing"
)

func TestMapResources(t *testing.T) {
	tests := []struct {
		name      string
		resources []string
		want      int
	}{
		{name: "with workload", resources: []string{"Workload"}, want: 7},
		{name: "dup resources", resources: []string{"Workload", "Pod", "Job"}, want: 7},
		{name: "empty resources", resources: []string{}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapResources(v1alpha1.Control{Resources: tt.resources})
			if len(got) != tt.want {
				t.Errorf("TestMapResources() = %v, want %v", len(got), tt.want)
			}
		})
	}
}
