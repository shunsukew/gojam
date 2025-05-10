GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: lint
lint:
	golangci-lint run --timeout=5m

.PHONY: test
test: build
	go test -v ./internal/...
	go test -v ./pkg/...

.PHONY: tiny-integration
tiny-integration: build
	go test -tags=tiny -v ./test/...

.PHONY: full-integration
full-integration: build
	go test -tags=full -v ./test/...

.PHONY: build-rust
build-rust:
	cargo build --release --manifest-path rust/bandersnatch-ring-vrf/Cargo.toml

.PHONY: cbindgen
cbindgen:
	cd ./rust/bandersnatch-ring-vrf && cbindgen --config cbindgen.toml --crate bandersnatch-ring-vrf --output include/bandersnatch-ring-vrf.h

.PHONY: build
build: build-rust cbindgen
	GOOS=${GOOS} GOARCH=${GOARCH} go build -o gojam ./cmd/main.go
