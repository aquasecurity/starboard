package compliance

import (
	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"testing"
)

func TestPredicate(t *testing.T) {
	RegisterFailHandler(ginkgo.Fail)
	suiteName := "Controller Suite"
	ginkgo.RunSpecs(t, suiteName)
}
