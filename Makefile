SOURCES := $(shell find . -name '*.go')
BINARY := starboard

build: starboard

qtc:
	go get -v -u github.com/valyala/quicktemplate/qtc
	qtc

$(BINARY): $(SOURCES)
	CGO_ENABLED=0 go build -o ./bin/$(BINARY) ./cmd/starboard/main.go

unit-tests: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...

integration-tests: build
	go test ./itest -ginkgo.v -ginkgo.progress -test.v
