package polaris

import (
	. "github.com/aquasecurity/starboard/itest/starboard-operator/configauditreport"
	. "github.com/onsi/ginkgo"
)

var _ = Describe("ConfigAuditReport Reconciler", SharedBehavior(&inputs))
