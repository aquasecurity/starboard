package compliance

import (
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"testing"
)

func TestMapResources(t *testing.T) {
	tests := []struct {
		name  string
		kinds []string
		want  int
	}{
		{name: "with workload", kinds: []string{"Workload"}, want: 7},
		{name: "dup kinds", kinds: []string{"Workload", "Pod", "Job"}, want: 7},
		{name: "empty kinds", kinds: []string{}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapKinds(v1alpha1.Control{Kinds: tt.kinds})
			if len(got) != tt.want {
				t.Errorf("TestMapResources() = %v, want %v", len(got), tt.want)
			}
		})
	}
}
