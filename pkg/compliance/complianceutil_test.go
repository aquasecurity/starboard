package compliance

import (
	"fmt"
	ctrl "sigs.k8s.io/controller-runtime"
	"testing"
)

func TestLoadClusterComplianceSpecs(t *testing.T) {
	log := ctrl.Log.WithName("job").WithName("compliance-report")
	specs, err := LoadClusterComplianceSpecs(log)
	if err != nil {
		t.Error(err)
	}
	if len(specs) == 0 {
		t.Error(fmt.Sprintf("TestLoadClusterComplianceSpecs want %d got %d", 1, len(specs)))
	}
}
