# Hardware HSM Setup Guide

This plugin works with any PKCS#11-compliant device. The steps below apply
generically to physical HSMs, smartcards, and USB security keys.

For SoftHSM2 (software emulation used in development and testing), see the
[README](../README.md).

---

## Prerequisites

### 1. Install the PKCS#11 library for your device

Every PKCS#11 device ships with (or requires you to install) a shared library:

| OS | Typical file extension |
|----|----------------------|
| Linux | `.so` |
| macOS | `.dylib` or `.so` |
| Windows | `.dll` |

Consult your device vendor's documentation for the exact library path.

### 2. Verify the device is visible

Use `pkcs11-tool` (from the `opensc` package) to confirm the library loads and
the device is recognised:

```bash
# List available tokens
pkcs11-tool --module <path-to-library> --list-tokens

# List objects on a token (requires login)
pkcs11-tool --module <path-to-library> \
  --token-label "<token-label>" --login --list-objects
```

---

## Generating a key pair on the HSM

Most PKCS#11 devices support key generation directly on the hardware so the
private key never leaves the device boundary.

```bash
# Generate an EC P-256 key pair
pkcs11-tool --module <path-to-library> \
  --token-label "<token-label>" --login \
  --keypairgen --mechanism EC --curve prime256v1 \
  --label "spire-node-key" --id 01
```

If your device requires vendor-specific tools for key generation, follow the
vendor's documentation. The key must be accessible via a standard PKCS#11
`C_FindObjects` / `C_Sign` interface.

---

## Obtaining a signed certificate

The SPIRE server validates the node certificate against a CA bundle. The leaf
certificate must have `KeyUsage: Digital Signature`.

### Option A — generate a CSR from the HSM key

```bash
# Using openssl with the pkcs11 engine (requires engine_pkcs11 / libp11)
openssl req -engine pkcs11 -keyform engine \
  -key "pkcs11:token=<token-label>;object=spire-node-key;type=private" \
  -new -out node.csr -subj "/CN=my-spire-node"

# Sign with your CA
openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out node.crt -days 365 \
  -extfile <(printf "keyUsage=critical,digitalSignature\n")
```

### Option B — import an externally generated certificate

If your device allows certificate import:

```bash
pkcs11-tool --module <path-to-library> \
  --token-label "<token-label>" --login \
  --write-object node.crt --type cert --label "spire-node-cert" --id 01
```

---

## Verifying the key works

Test signing before configuring SPIRE:

```bash
echo "test" > /tmp/test.txt
pkcs11-tool --module <path-to-library> \
  --token-label "<token-label>" --login \
  --sign --mechanism ECDSA --id 01 \
  --input-file /tmp/test.txt --output-file /tmp/sig.bin
echo "signing succeeded"
```

---

## SPIRE agent configuration

```hcl
NodeAttestor "x509pop_pkcs11" {
  plugin_cmd = "/usr/local/bin/nodeattestor-pkcs11-agent"
  plugin_data {
    # Path to the PKCS#11 shared library provided by your device vendor.
    module_path = "/usr/lib/<vendor>/libpkcs11.so"

    # Token label shown by pkcs11-tool --list-tokens.
    token_label = "<token-label>"

    # User PIN. Use pin_env in production to avoid storing it in config.
    pin_env = "PKCS11_PIN"

    # Key identifier (hex CKA_ID) and/or label used when the key was created.
    key_id    = "01"
    key_label = "spire-node-key"

    # Leaf certificate in PEM format (signed by the CA bundle on the server).
    certificate_path = "/etc/spire/agent/node.crt.pem"
  }
}
```

---

## Compatibility notes

- **Key types**: ECDSA (P-256, P-384, P-521) and RSA are supported. The hash
  algorithm is selected automatically based on the key type and curve.
- **Mechanisms**: the plugin uses `CKM_ECDSA` (raw, pre-hashed) and
  `CKM_RSA_PKCS`. Devices that do not expose these mechanisms are not
  compatible.
- **Session model**: one session is opened at `Configure` time and held open
  for the lifetime of the agent process. Devices that enforce strict session
  limits may need configuration adjustments.
- **Tested with**: SoftHSM2 on Linux, macOS, and Windows. Other PKCS#11
  devices should work if they implement the standard interface correctly, but
  have not been independently verified.
