package conftest

import (
	. "github.com/aquasecurity/trivy-operator/itest/starboard-operator/behavior"
	. "github.com/onsi/ginkgo"
)

var _ = Describe("Conftest", ConfigurationCheckerBehavior(&inputs))
