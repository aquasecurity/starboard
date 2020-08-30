SOURCES := $(shell find . -name '*.go')
BINARY := starboard

GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

build: $(BINARY)

.PHONY: get-ginkgo
## get-ginkgo Installs Ginkgo CLI.
get-ginkgo:
	go install github.com/onsi/ginkgo/ginkgo

.PHONY: get-qtc
## get-qtc Installs quicktemplate compiler.
get-qtc:
	go install github.com/valyala/quicktemplate/qtc

.PHONY: compile-templates
## compile-templates Converts quicktemplate files (*.qtpl) into Go code.
compile-templates: get-qtc
	$(GOBIN)/qtc

$(BINARY): $(SOURCES)
	CGO_ENABLED=0 go build -o ./bin/$(BINARY) ./cmd/starboard/main.go

.PHONY: test
## test will run both unit tests and integration tests
test: unit-tests integration-tests

.PHONY: unit-tests
## unit-tests Runs unit tests with codecov enabled.
unit-tests: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...

.PHONY: integration-tests
## integration-tests Runs integration tests with codecov enabled.
integration-tests: get-ginkgo
	$(GOBIN)/ginkgo \
	--progress \
	--v \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/aquasecurity/starboard/pkg/cmd,\
	github.com/aquasecurity/starboard/pkg/kube \
	github.com/aquasecurity/starboard/pkg/kubebench \
	github.com/aquasecurity/starboard/pkg/kubehunter \
	github.com/aquasecurity/starboard/pkg/polaris \
	github.com/aquasecurity/starboard/pkg/find/vulnerabilities/trivy \
	github.com/aquasecurity/starboard/pkg/find/vulnerabilities/crd \
	./itest

.PHONY: clean
clean:
	rm -r ./bin
	rm -r ./dist
