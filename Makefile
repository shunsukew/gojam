GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: lint
lint:
	golangci-lint run --timeout=5m

.PHONY: build
build:
	GOOS=${GOOS} GOARCH=${GOARCH} go build -o gojam ./cmd/main.go
