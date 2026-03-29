# Makefile for spire-plugin-node-attestor-x509pop-pkcs11
# Builds two binaries: node attestor agent (requires CGo) and server.

GOOS   ?= linux
GOARCH ?= amd64
OUT    ?= bin

.PHONY: all build test lint clean

all: build

build: $(OUT)/spire-plugin-pkcs11-agent \
       $(OUT)/spire-plugin-pkcs11-server

# Agent binary requires CGO_ENABLED=1 for miekg/pkcs11.
$(OUT)/spire-plugin-pkcs11-agent:
	@mkdir -p $(OUT)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go build -o $@ ./cmd/nodeattestor-pkcs11-agent

# Server binary is pure Go; no CGo needed.
$(OUT)/spire-plugin-pkcs11-server:
	@mkdir -p $(OUT)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $@ ./cmd/nodeattestor-pkcs11-server

test:
	CGO_ENABLED=1 go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(OUT)
