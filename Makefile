BINARY      := releaseguard
MODULE      := github.com/Helixar-AI/ReleaseGuard
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS     := -s -w -X main.version=$(VERSION)
BUILD_DIR   := ./bin
DIST_DIR    := ./dist

.PHONY: all build clean test lint fmt vet install dev-setup cross-build

## all: build the binary
all: build

## build: compile releaseguard for the current platform
build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/releaseguard
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

## install: install releaseguard to GOPATH/bin
install:
	go install -ldflags="$(LDFLAGS)" ./cmd/releaseguard

## dev-setup: install development tools
dev-setup:
	go mod download
	@which golangci-lint > /dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Dev environment ready."

## test: run all tests with race detector
test:
	go test -race -count=1 ./...

## test-cover: run tests with coverage report
test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format all Go source files
fmt:
	gofmt -w .

## tidy: tidy go.mod and go.sum
tidy:
	go mod tidy

## cross-build: build for all supported platforms
cross-build:
	@mkdir -p $(DIST_DIR)
	GOOS=linux   GOARCH=amd64  go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-linux-amd64   ./cmd/releaseguard
	GOOS=linux   GOARCH=arm64  go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-linux-arm64   ./cmd/releaseguard
	GOOS=darwin  GOARCH=amd64  go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-darwin-amd64  ./cmd/releaseguard
	GOOS=darwin  GOARCH=arm64  go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-darwin-arm64  ./cmd/releaseguard
	GOOS=windows GOARCH=amd64  go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-windows-amd64.exe ./cmd/releaseguard
	@echo "Cross-compiled binaries in $(DIST_DIR)/"

## demo: run a quick check against the examples/react-dist fixture
demo: build
	$(BUILD_DIR)/$(BINARY) init || true
	$(BUILD_DIR)/$(BINARY) check ./examples/react-dist

## clean: remove build artifacts
clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR) coverage.out coverage.html

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
