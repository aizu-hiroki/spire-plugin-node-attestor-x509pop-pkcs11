# Hardware HSM Setup Guide

This guide covers setup for physical PKCS#11 devices. For SoftHSM2 (software
emulation used in development and testing), see the [README](../README.md).

---

## YubiKey 5 (PIV)

YubiKey 5 series supports PKCS#11 via its PIV (Personal Identity Verification)
application.

### Prerequisites

Install the YubiKey PKCS#11 library:

```bash
# Ubuntu / Debian
sudo apt-get install -y ykcs11

# macOS (Homebrew)
brew install yubico-piv-tool

# Windows
# Install YubiKey Minidriver or the Yubico PIV Tool from
# https://developers.yubico.com/yubico-piv-tool/Releases/
```

Library paths:

| OS | Path |
|----|------|
| Linux | `/usr/lib/x86_64-linux-gnu/libykcs11.so` |
| macOS (Homebrew) | `/opt/homebrew/lib/libykcs11.dylib` |
| Windows | `C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll` |

### Generate a key and certificate on the YubiKey

```bash
# Generate EC P-256 key in slot 9a (Authentication)
yubico-piv-tool -a generate -s 9a -A ECCP256 -o pubkey.pem

# Create a self-signed certificate (or use a CA-signed one)
yubico-piv-tool -a verify-pin -a selfsign-certificate \
  -s 9a -S "/CN=my-spire-node/" --valid-days=3650 \
  -i pubkey.pem -o node.crt.pem

# Import the certificate into the YubiKey
yubico-piv-tool -a import-certificate -s 9a -i node.crt.pem
```

To use a CA-signed certificate instead:

```bash
# Generate a CSR
yubico-piv-tool -a verify-pin -a request-certificate \
  -s 9a -S "/CN=my-spire-node/" -i pubkey.pem -o node.csr

# Sign with your CA (example using openssl)
openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out node.crt -days 365

# Import signed cert
yubico-piv-tool -a import-certificate -s 9a -i node.crt
```

### SPIRE agent configuration

```hcl
NodeAttestor "x509pop_pkcs11" {
  plugin_cmd = "/usr/local/bin/nodeattestor-pkcs11-agent"
  plugin_data {
    module_path  = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
    token_label  = "YubiKey PIV #12345678"  # shown by pkcs11-tool --list-tokens
    pin_env      = "PKCS11_PIN"             # YubiKey PIV PIN (default: 123456)
    key_id       = "01"                     # slot 9a = object ID 01
    certificate_path = "/etc/spire/agent/node.crt.pem"
  }
}
```

Find the exact token label:

```bash
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libykcs11.so --list-tokens
```

### PIV slot to PKCS#11 object ID mapping

| PIV slot | Purpose | PKCS#11 ID |
|----------|---------|------------|
| 9a | Authentication | `01` |
| 9c | Digital Signature | `02` |
| 9d | Key Management | `03` |
| 9e | Card Authentication | `04` |

---

## Thales (Gemalto) Luna HSM

### Prerequisites

Install the Thales Luna PKCS#11 client software (vendor-provided). The library
is typically located at:

```
/usr/safenet/lunaclient/lib/libCryptoki2_64.so   # Linux
```

### Initialise a partition and import a key

Use Thales `lunacm` or `cmu` tools to:

1. Create or select an HSM partition
2. Generate or import an EC/RSA key pair
3. Note the key label and CKA_ID

```bash
# List objects on the token
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2_64.so \
  --list-objects --login
```

### SPIRE agent configuration

```hcl
NodeAttestor "x509pop_pkcs11" {
  plugin_cmd = "/usr/local/bin/nodeattestor-pkcs11-agent"
  plugin_data {
    module_path  = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
    token_label  = "my-partition"
    pin_env      = "PKCS11_PIN"
    key_label    = "spire-node-key"
    certificate_path = "/etc/spire/agent/node.crt.pem"
  }
}
```

---

## AWS CloudHSM

AWS CloudHSM provides a PKCS#11 library as part of the CloudHSM client
software.

### Prerequisites

Install the CloudHSM client and PKCS#11 library following the
[AWS documentation](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html).

Library path (Linux): `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`

### SPIRE agent configuration

```hcl
NodeAttestor "x509pop_pkcs11" {
  plugin_cmd = "/usr/local/bin/nodeattestor-pkcs11-agent"
  plugin_data {
    module_path  = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
    token_label  = "cavium"   # CloudHSM uses "cavium" as the token label
    pin_env      = "PKCS11_PIN"   # <CU_username>:<password>
    key_label    = "spire-node-key"
    certificate_path = "/etc/spire/agent/node.crt.pem"
  }
}
```

---

## General: verifying a device with pkcs11-tool

Before configuring the plugin, verify your device is visible and the key is
importable using `pkcs11-tool` (from the `opensc` package):

```bash
# List available tokens
pkcs11-tool --module <path-to-library> --list-tokens

# List objects on a token
pkcs11-tool --module <path-to-library> \
  --token-label "<token-label>" --login --list-objects

# Test signing (verifies the key works)
echo "test" | pkcs11-tool --module <path-to-library> \
  --token-label "<token-label>" --login \
  --sign --mechanism ECDSA --id <key-id> -o sig.bin
```

---

## Preparing a CA-signed certificate

All HSM configurations require a certificate signed by the CA bundle loaded
into the SPIRE server.

```bash
# 1. Generate a CSR from the key already on the HSM
pkcs11-tool --module <library> --token-label "<label>" --login \
  --sign --mechanism ECDSA-SHA256 ... # or use openssl with the PKCS#11 engine

# 2. Sign the CSR with your CA
openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out node.crt -days 365 \
  -extfile <(printf "keyUsage=digitalSignature\n")

# 3. Verify the certificate has digitalSignature key usage
openssl x509 -in node.crt -text -noout | grep -A2 "Key Usage"
```

> **Required**: The leaf certificate must have `KeyUsage: Digital Signature`.
> The plugin rejects certificates that lack this usage.
