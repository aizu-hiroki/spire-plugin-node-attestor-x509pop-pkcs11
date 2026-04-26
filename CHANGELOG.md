# Changelog

## [v0.2.0] - 2026-04-26

### Added

- **PKCS#11 certificate storage**: the node certificate can now be stored as a
  `CKO_CERTIFICATE` object on the PKCS#11 token alongside the private key.
  Omitting `certificate_path` from the agent configuration enables this mode —
  the plugin loads the certificate directly from the token using `key_id` /
  `key_label` as the lookup identifier (standard PKCS#11 `CKA_ID` pairing
  convention).
- New optional agent config fields for fine-grained PKCS#11 certificate lookup:
  - `cert_id` / `cert_label` — override the certificate object identifier
    (defaults to `key_id` / `key_label` when omitted)
  - `intermediates_id` / `intermediates_label` — load an intermediate
    certificate from the token
- `Client.LoadCertificate()` method and `LoadCertificate()` package function
  in the internal PKCS#11 client (`internal/pkcs11`).
- `CertImportedToToken` field in `TestEnv` and automatic `pkcs11-tool`-based
  certificate import in `SetupSoftHSM` for integration testing.
- SoftHSM2 library search extended to versioned Homebrew Cellar paths on macOS
  (`/usr/local/Cellar/softhsm/*/lib/softhsm/libsofthsm2.so`).

### Changed

- `certificate_path` is now **optional** (was required). Omitting it switches
  the plugin to PKCS#11-based certificate loading. File-based behaviour is
  fully preserved when `certificate_path` is set.

### Dependencies

- Bumped `actions/checkout` to v6
- Bumped `actions/setup-go` to v6
- Bumped go module dependencies (`purego`, `spire-plugin-sdk`, `grpc`, etc.)

---

## [v0.1.1] - 2026-04-16

- Dependency updates (go modules and GitHub Actions).

## [v0.1.0] - 2026-03-30

- Initial release.
- PKCS#11-backed private key for x509pop node attestation (no CGo).
- ECDSA P-256 / P-384 / P-521 and RSA PKCS#1 v1.5 support.
- Cross-platform: macOS, Linux, Windows.
- SoftHSM2 integration tests.
