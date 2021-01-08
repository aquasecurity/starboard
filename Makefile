# Set the default goal
.DEFAULT_GOAL := build

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

SOURCES := $(shell find . -name '*.go')

IMAGE_TAG := dev
STARBOARD_CLI_IMAGE := aquasec/starboard:$(IMAGE_TAG)
STARBOARD_OPERATOR_IMAGE := aquasec/starboard-operator:$(IMAGE_TAG)
STARBOARD_SCANNER_AQUA_IMAGE := aquasec/starboard-scanner-aqua:$(IMAGE_TAG)

MKDOCS_IMAGE := squidfunk/mkdocs-material:6.1.7
MKDOCS_PORT := 8000

.PHONY: all
all: build

.PHONY: build
build: build-starboard-cli build-starboard-operator build-starboard-scanner-aqua

## Builds the starboard binary
build-starboard-cli: $(SOURCES)
	CGO_ENABLED=0 go build -o ./bin/starboard ./cmd/starboard/main.go

## Builds the starboard-operator binary
build-starboard-operator: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/starboard-operator ./cmd/starboard-operator/main.go

## Builds the scanner-aqua binary
build-starboard-scanner-aqua: $(SOURCES)
	CGO_ENABLED=0 GOOS=linux go build -o ./bin/starboard-scanner-aqua ./cmd/scanner-aqua/main.go

.PHONY: get-ginkgo
## Installs Ginkgo CLI
get-ginkgo:
	go install github.com/onsi/ginkgo/ginkgo

.PHONY: get-qtc
## Installs quicktemplate compiler
get-qtc:
	go install github.com/valyala/quicktemplate/qtc

.PHONY: compile-templates
## Converts quicktemplate files (*.qtpl) into Go code
compile-templates: get-qtc
	$(GOBIN)/qtc

.PHONY: test
## Runs both unit and integration tests
test: unit-tests integration-tests

.PHONY: unit-tests
## Runs unit tests with code coverage enabled
unit-tests: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt ./...

.PHONY: itests-starboard
## Runs integration tests for Starboard CLI with code coverage enabled
itests-starboard: check-env get-ginkgo
	$(GOBIN)/ginkgo \
	--progress \
	--v \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/aquasecurity/starboard/pkg/cmd,\
	github.com/aquasecurity/starboard/pkg/kube,\
	github.com/aquasecurity/starboard/pkg/kube/pod,\
	github.com/aquasecurity/starboard/pkg/kubebench,\
	github.com/aquasecurity/starboard/pkg/kubehunter,\
	github.com/aquasecurity/starboard/pkg/polaris,\
	github.com/aquasecurity/starboard/pkg/configauditreport,\
	github.com/aquasecurity/starboard/pkg/trivy,\
	github.com/aquasecurity/starboard/pkg/vulnerabilityreport \
	./itest/starboard

.PHONY: itests-starboard-operator
## Runs integration tests for Starboard Operator with code coverage enabled
itests-starboard-operator: check-env get-ginkgo
	$(GOBIN)/ginkgo \
	--progress \
	--v \
	-coverprofile=coverage.txt \
	-coverpkg=github.com/aquasecurity/starboard/pkg/operator,\
	github.com/aquasecurity/starboard/pkg/operator/controller,\
	github.com/aquasecurity/starboard/pkg/operator/controller/job,\
	github.com/aquasecurity/starboard/pkg/operator/controller/pod,\
	github.com/aquasecurity/starboard/pkg/operator/logs,\
	github.com/aquasecurity/starboard/pkg/trivy,\
	github.com/aquasecurity/starboard/pkg/vulnerabilityreport \
	./itest/starboard-operator

check-env:
ifndef KUBECONFIG
	$(error Environment variable KUBECONFIG is not set)
endif

.PHONY: clean
## Removes build artifacts
clean:
	@rm -r ./bin 2> /dev/null || true
	@rm -r ./dist 2> /dev/null || true

.PHONY: docker-build
## Builds Docker images for all binaries
docker-build: docker-build-starboard-cli docker-build-starboard-operator docker-build-starboard-scanner-aqua

## Builds Docker image for Starboard CLI
docker-build-starboard-cli: build-starboard-cli
	docker build --no-cache -t $(STARBOARD_CLI_IMAGE) -f build/starboard/Dockerfile bin

## Builds Docker image for Starboard operator
docker-build-starboard-operator: build-starboard-operator
	docker build --no-cache -t $(STARBOARD_OPERATOR_IMAGE) -f build/starboard-operator/Dockerfile bin

## Builds Docker image for Aqua scanner
docker-build-starboard-scanner-aqua: build-starboard-scanner-aqua
	docker build --no-cache -t $(STARBOARD_SCANNER_AQUA_IMAGE) -f build/scanner-aqua/Dockerfile bin

.PHONY: mkdocs-serve
## Runs MkDocs development server to preview the documentation page
mkdocs-serve:
	docker run --name mkdocs-serve --rm -v $(PWD):/docs -p $(MKDOCS_PORT):8000 $(MKDOCS_IMAGE)
