package starboard_operator

import (
	. "github.com/aquasecurity/starboard/itest/starboard-operator/behavior"
	. "github.com/onsi/ginkgo"
)

var _ = Describe("Starboard Operator", func() {

	// TODO Refactor to run this container in a separate test suite
	Describe("Vulnerability Scanner", VulnerabilityScannerBehavior(&inputs))

	// TODO Refactor to run this container in a separate test suite
	Describe("Configuration Checker", ConfigurationCheckerBehavior(&inputs))

	// TODO Refactor to run this container in a separate test suite
	Describe("CIS Kubernetes Benchmark", CISKubernetesBenchmarkBehavior(&inputs))

})
