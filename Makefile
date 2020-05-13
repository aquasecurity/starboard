SOURCES := $(shell find . -name '*.go')
BINARY := starboard

build: starboard

$(BINARY): $(SOURCES)
	CGO_ENABLED=0 go build -o ./bin/$(BINARY) ./cmd/starboard/main.go

test: $(SOURCES)
	go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...
