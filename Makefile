# Makefile for spire-plugin-node-attestor-x509pop-pkcs11
# Builds two binaries: node attestor agent and server.

GOOS   ?= linux
GOARCH ?= amd64
OUT    ?= bin

# Platforms for cross-compilation
AGENT_TARGETS := \
	darwin_amd64 \
	darwin_arm64 \
	linux_amd64 \
	linux_arm64 \
	windows_amd64 \
	windows_arm64

SERVER_TARGETS := \
	linux_amd64 \
	linux_arm64

.PHONY: all build build-all build-agent build-server \
        $(addprefix agent-,$(AGENT_TARGETS)) \
        $(addprefix server-,$(SERVER_TARGETS)) \
        test lint clean test-yubikey

all: build

build: $(OUT)/spire-plugin-pkcs11-agent \
       $(OUT)/spire-plugin-pkcs11-server

$(OUT)/spire-plugin-pkcs11-agent:
	@mkdir -p $(OUT)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -o $@ ./cmd/nodeattestor-pkcs11-agent

$(OUT)/spire-plugin-pkcs11-server:
	@mkdir -p $(OUT)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -o $@ ./cmd/nodeattestor-pkcs11-server

# Cross-compilation: agent for all platforms
agent-darwin_amd64:
	@mkdir -p $(OUT)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o $(OUT)/spire-plugin-pkcs11-agent_darwin_amd64 ./cmd/nodeattestor-pkcs11-agent

agent-darwin_arm64:
	@mkdir -p $(OUT)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o $(OUT)/spire-plugin-pkcs11-agent_darwin_arm64 ./cmd/nodeattestor-pkcs11-agent

agent-linux_amd64:
	@mkdir -p $(OUT)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(OUT)/spire-plugin-pkcs11-agent_linux_amd64 ./cmd/nodeattestor-pkcs11-agent

agent-linux_arm64:
	@mkdir -p $(OUT)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(OUT)/spire-plugin-pkcs11-agent_linux_arm64 ./cmd/nodeattestor-pkcs11-agent

agent-windows_amd64:
	@mkdir -p $(OUT)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $(OUT)/spire-plugin-pkcs11-agent_windows_amd64.exe ./cmd/nodeattestor-pkcs11-agent

agent-windows_arm64:
	@mkdir -p $(OUT)
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o $(OUT)/spire-plugin-pkcs11-agent_windows_arm64.exe ./cmd/nodeattestor-pkcs11-agent

# Cross-compilation: server for Linux only
server-linux_amd64:
	@mkdir -p $(OUT)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(OUT)/spire-plugin-pkcs11-server_linux_amd64 ./cmd/nodeattestor-pkcs11-server

server-linux_arm64:
	@mkdir -p $(OUT)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(OUT)/spire-plugin-pkcs11-server_linux_arm64 ./cmd/nodeattestor-pkcs11-server

# Build all cross-compiled binaries
build-agent: $(addprefix agent-,$(AGENT_TARGETS))
build-server: $(addprefix server-,$(SERVER_TARGETS))
build-all: build-agent build-server

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
