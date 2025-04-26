GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: lint
lint:
	golangci-lint run --timeout=5m

.PHONY: test
test:
	go test -v ./...

.PHONY: build-rust
build-rust:
	cargo build --release --manifest-path rust/bandersnatch-ring-vrf/Cargo.toml

.PHONY: cbindgen
cbindgen:
	cd ./rust/bandersnatch-ring-vrf && cbindgen --config cbindgen.toml --crate bandersnatch-ring-vrf --output headers/ringvrf.h

.PHONY: build
build: build-rust cbindgen
	GOOS=${GOOS} GOARCH=${GOARCH} go build -o gojam ./cmd/main.go
