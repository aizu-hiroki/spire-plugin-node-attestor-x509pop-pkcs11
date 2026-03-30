# Makefile for spire-plugin-node-attestor-x509pop-pkcs11
# Builds two binaries: node attestor agent (requires CGo) and server.

GOOS   ?= linux
GOARCH ?= amd64
OUT    ?= bin

.PHONY: all build test lint clean test-yubikey

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

# test-yubikey runs integration tests that require a physical YubiKey 5 series
# connected via USB. PIV slot 9a will be overwritten with a freshly generated
# test key and certificate.
#
# Prerequisites (see docs/hardware_setup.md — YubiKey 5 Series section):
#   macOS:   brew install yubico-yubikey-manager yubico-piv-tool
#   Linux:   apt install yubikey-manager yubico-piv-tool
#   Windows: install Yubico PIV Tool + YubiKey Manager from yubico.com
#
# Optional env vars:
#   YUBIKEY_PIN — PIV PIN (default: 123456)
#
# Example:
#   make test-yubikey
#   YUBIKEY_PIN=mypin make test-yubikey
test-yubikey:
	CGO_ENABLED=1 go test -tags yubikey -v -count=1 -timeout 120s ./...

clean:
	rm -rf $(OUT)
