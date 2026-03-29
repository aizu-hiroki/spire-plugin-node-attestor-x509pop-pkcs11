# spire-plugin-node-attestor-x509pop-pkcs11

A [SPIRE](https://github.com/spiffe/spire) node attestation plugin that uses PKCS#11-backed private keys (HSM, smartcard, YubiKey, or SoftHSM2) for [X.509 Proof-of-Possession](https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_x509pop.md) (x509pop) node attestation.

## Overview

Standard x509pop reads the private key from a PEM file.  This plugin keeps the private key inside a PKCS#11 token so it never leaves the hardware boundary.  The attestation flow is identical to x509pop — the only difference is *where* the signing key lives.

```
Agent (PKCS#11 token)              Server
        |                              |
        |-- 1. X.509 cert chain -----> |
        |                              |-- 2. Verify chain against CA bundle
        |                              |-- 3. Generate random nonce
        |<-- 4. Challenge (nonce) ---- |
        |                              |
        | (sign nonce on HSM)          |
        |-- 5. Signature ------------> |
        |                              |-- 6. Verify signature with leaf cert
        |                              |-- 7. Return SPIFFE ID + selectors
```

### Key features

- **No CGo** — uses [purego](https://github.com/ebitengine/purego) on Unix and `syscall` on Windows for dynamic PKCS#11 library loading.
- **Cross-platform** — macOS (external HSM via PKCS#11), Linux, Windows.
- **Multi-algorithm** — ECDSA P-256 / P-384 / P-521 and RSA (PKCS#1 v1.5).
- **SoftHSM2 compatible** — full end-to-end testing without physical hardware.

---

## Requirements

| Component | Version |
|-----------|---------|
| Go        | 1.21+   |
| SPIRE     | 1.x     |
| PKCS#11 library | SoftHSM2, YubiKey PKCS#11, or any compliant library |

For testing only: [SoftHSM2](https://github.com/opendnssec/SoftHSMv2) + `softhsm2-util`

---

## Building

```bash
# Agent binary
go build -o nodeattestor-pkcs11-agent ./cmd/nodeattestor-pkcs11-agent

# Server binary
go build -o nodeattestor-pkcs11-server ./cmd/nodeattestor-pkcs11-server

# Or use Make (cross-compile with GOOS/GOARCH)
make
```

The agent binary does **not** require CGo (`CGO_ENABLED=0` works on all platforms).

---

## SPIRE Configuration

### Server (`spire-server.conf`)

```hcl
NodeAttestor "x509pop_pkcs11" {
  plugin_cmd = "/usr/local/bin/nodeattestor-pkcs11-server"
  plugin_data {
    # Path to PEM file containing trusted CA certificate(s).
    ca_bundle_path = "/opt/spire/conf/server/ca.pem"

    # Allow nodes to re-attest (default: false).
    allow_reattestation = true
  }
}
```

### Agent (`spire-agent.conf`)

```hcl
NodeAttestor "x509pop_pkcs11" {
  plugin_cmd = "/usr/local/bin/nodeattestor-pkcs11-agent"
  plugin_data {
    # PKCS#11 library path.
    module_path = "/usr/lib/softhsm/libsofthsm2.so"

    # Token label (set during token initialisation).
    token_label = "spire-node"

    # User PIN — prefer pin_env for production.
    # pin = "1234"
    pin_env = "PKCS11_PIN"

    # Key identifier (hex) and/or label.
    key_id    = "01"
    key_label = "node-key"

    # Node certificate (leaf) in PEM format.
    certificate_path = "/opt/spire/conf/agent/node.crt.pem"

    # Optional intermediate certificate(s) in PEM format.
    # intermediates_path = "/opt/spire/conf/agent/intermediate.crt.pem"
  }
}
```

> **Security note**: Avoid storing the PIN in the configuration file in production.
> Use `pin_env` to read the PIN from an environment variable instead.

---

## SPIFFE ID and selectors

**Agent SPIFFE ID**

```
spiffe://<trust-domain>/spire/agent/x509pop_pkcs11/<sha256-of-leaf-cert-DER>
```

**Selectors**

| Selector | Example |
|----------|---------|
| `subject:cn:<CN>` | `subject:cn:my-node` |
| `serial:<serial>` | `serial:42` |
| `uri:<URI SAN>` | `uri:spiffe://example.org/node` |
| `dns:<DNS SAN>` | `dns:node.example.org` |

---

## SoftHSM2 setup (development / testing)

### 1. Install SoftHSM2

```bash
# Ubuntu / Debian
sudo apt-get install -y softhsm2

# macOS (Homebrew)
brew install softhsm

# Windows
# Download installer from https://github.com/opendnssec/SoftHSMv2/releases
```

### 2. Generate a CA and node certificate

```bash
# Self-signed CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 \
  -subj "/CN=My SPIRE CA"

# Node key and certificate signed by the CA
openssl ecparam -name prime256v1 -genkey -noout -out node.key
openssl req -new -key node.key -out node.csr -subj "/CN=my-node"
openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out node.crt -days 365
```

### 3. Import the node key into SoftHSM2

```bash
# Initialise a token
softhsm2-util --init-token --free \
  --label "spire-node" --pin 1234 --so-pin 5678

# Convert key to PKCS#8 PEM and import
openssl pkcs8 -topk8 -nocrypt -in node.key -out node.key.p8.pem
softhsm2-util --import node.key.p8.pem \
  --token "spire-node" --label "node-key" --id 01 --pin 1234
```

### 4. Run tests

```bash
go test ./...
```

SoftHSM2-dependent tests are automatically skipped when the library is not found.

---

## Supported hardware

Any PKCS#11-compliant device should work provided it exposes `CKM_ECDSA` or
`CKM_RSA_PKCS`.  SoftHSM2 is the only device verified by the automated test
suite.  See [docs/hardware_setup.md](docs/hardware_setup.md) for generic setup
instructions.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | Internal design, No CGo approach, attestation flow |
| [docs/pkcs11_abi.md](docs/pkcs11_abi.md) | PKCS#11 ABI cross-platform details (CK_ULONG, struct packing) |
| [docs/hardware_setup.md](docs/hardware_setup.md) | YubiKey, Thales Luna, AWS CloudHSM setup |
| [docs/node_attestation_flowchart.md](docs/node_attestation_flowchart.md) | Sequence diagram |

---

## License

[Apache 2.0](LICENSE)
