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

## YubiKey 5 Series

The YubiKey 5 Series provides a PKCS#11 interface through its PIV application.
This section describes how to perform node attestation using a YubiKey.

### Prerequisites

**macOS**
```bash
brew install yubico-yubikey-manager yubico-piv-tool
```

**Linux (Debian/Ubuntu)**
```bash
apt install yubikey-manager yubico-piv-tool
# or: pip install yubikey-manager
```

**Windows**

Install the following from the official Yubico website:
- [Yubico PIV Tool](https://developers.yubico.com/yubico-piv-tool/) (includes libykcs11.dll)
- [YubiKey Manager](https://www.yubico.com/support/download/yubikey-manager/) (provides the `ykman` command)

### Library paths

| OS | Library path |
|----|--------------|
| macOS (Apple Silicon) | `/opt/homebrew/lib/libykcs11.dylib` |
| macOS (Intel) | `/usr/local/lib/libykcs11.dylib` |
| Linux (x86\_64) | `/usr/lib/x86_64-linux-gnu/libykcs11.so` |
| Linux (other) | `/usr/lib/libykcs11.so` or `/usr/local/lib/libykcs11.so` |
| Windows | `C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll` |

**Minimum version**: libykcs11 >= 2.3.0 is required. Older versions do not
expose `CKO_PUBLIC_KEY` objects, which causes the plugin to fail to connect.

### PIV slot layout

This plugin uses PIV slot **9a (Authentication)**.
ykcs11 maps slot 9a to `CKA_ID = 0x01`, so set `key_id = "01"` in the SPIRE configuration.

### Integration tests

> **WARNING**: Running the tests overwrites the key and certificate in PIV slot 9a.
> Do not run them on a YubiKey that holds production credentials.

```bash
# Run with the YubiKey connected via USB
make test-yubikey

# If the PIN is not 123456
YUBIKEY_PIN=mypin make test-yubikey

# If the management key has been changed
YUBIKEY_MANAGEMENT_KEY=<hex-key> make test-yubikey
```

The tests are skipped automatically if no YubiKey is connected or the required tools are missing.

### Manual setup (production)

**Step 1 — Generate a key on the YubiKey**

```bash
ykman piv keys generate \
  --management-key <mgmt-key> \
  --pin-policy once \
  --touch-policy never \
  --algorithm ECCP256 \
  9a pubkey.pem
```

**Step 2 — Generate a CSR and have it signed by the CA**

```bash
# Generate the CSR via the pkcs11 engine
openssl req -engine pkcs11 -keyform engine \
  -key "pkcs11:token=YubiKey PIV #<serial>;object=PIV AUTH key;type=private" \
  -new -out node.csr -subj "/CN=my-spire-node"

# Sign with the CA (KeyUsage: digitalSignature is required)
openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out node.crt -days 365 \
  -extfile <(printf "keyUsage=critical,digitalSignature\n")
```

**Step 3 — Import the certificate into the YubiKey**

```bash
ykman piv certificates import --management-key <mgmt-key> --pin <pin> 9a node.crt
```

**Step 4 — Find the token label**

```bash
pkcs11-tool --module <path-to-libykcs11> --list-tokens
# or
ykman list  # shows the serial number
```

The token label has the form `YubiKey PIV #<serial>`.

**Step 5 — Configure the SPIRE agent**

```hcl
NodeAttestor "x509pop_pkcs11" {
  plugin_cmd = "/usr/local/bin/nodeattestor-pkcs11-agent"
  plugin_data {
    # macOS (Apple Silicon)
    module_path = "/opt/homebrew/lib/libykcs11.dylib"

    # Check with `ykman list` or `pkcs11-tool --list-tokens`
    token_label = "YubiKey PIV #12345678"

    # Passing the PIN via an environment variable is recommended
    pin_env = "PKCS11_PIN"

    # slot 9a = CKA_ID 0x01
    key_id = "01"

    certificate_path = "/etc/spire/agent/node.crt.pem"
  }
}
```

### Known limitations

- **libykcs11 >= 2.3.0 required**: older versions do not expose `CKO_PUBLIC_KEY` objects for ECC keys.
- **Sessions**: one session per process. Running multiple plugin instances against the same YubiKey is not recommended.
- **Touch policy**: the tests run with `--touch-policy never`. For production, `once` or `always` is recommended.

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
