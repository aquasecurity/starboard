package compliance

import (
	"fmt"
	"testing"
)

func TestLoadClusterComplianceSpecs(t *testing.T) {
	specs, err := LoadClusterComplianceSpecs()
	if err != nil {
		t.Error(err)
	}
	if len(specs) == 0 {
		t.Error(fmt.Sprintf("TestLoadClusterComplianceSpecs want %d got %d", 1, len(specs)))
	}
}
