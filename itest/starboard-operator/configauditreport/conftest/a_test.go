package conftest

import (
	. "github.com/aquasecurity/starboard/itest/starboard-operator/behavior"
	. "github.com/onsi/ginkgo"
)

var _ = Describe("Conftest", ConfigurationCheckerBehavior(&inputs))
