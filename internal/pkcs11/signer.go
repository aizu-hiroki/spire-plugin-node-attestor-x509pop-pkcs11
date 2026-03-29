// Package pkcs11 provides a pure-Go (no CGo) wrapper for PKCS#11 operations
// needed by the x509pop_pkcs11 SPIRE node attestation plugin.
package pkcs11

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"unsafe"
)

// Named EC curve OIDs (RFC 5480).
var (
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// DigestInfo prefixes for PKCS#1 v1.5 (CKM_RSA_PKCS) signing.
// These are the DER-encoded AlgorithmIdentifier sequences prepended to the
// hash value to form the DigestInfo structure (RFC 8017 §9.2).
var (
	digestInfoPrefixSHA256 = []byte{
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20,
	}
	digestInfoPrefixSHA384 = []byte{
		0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
		0x00, 0x04, 0x30,
	}
	digestInfoPrefixSHA512 = []byte{
		0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
		0x00, 0x04, 0x40,
	}
)

// Config holds the parameters needed to open a PKCS#11 session and locate a
// signing key on the token.
type Config struct {
	// ModulePath is the path to the PKCS#11 shared library.
	ModulePath string

	// TokenLabel identifies the token/slot to use.
	TokenLabel string

	// PIN is the user PIN for the token.
	PIN string

	// KeyID is the CKA_ID of the key to use (raw bytes).
	KeyID []byte

	// KeyLabel is the CKA_LABEL of the key to use.
	KeyLabel string
}

// Client wraps a PKCS#11 session and provides a crypto.Signer.
type Client struct {
	mod     *Module
	session CK_ULONG
	privKey CK_ULONG
	pubKey  crypto.PublicKey
}

// NewClient opens a PKCS#11 session, logs in, and locates the signing key.
func NewClient(cfg *Config) (*Client, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("module_path is required")
	}
	if cfg.TokenLabel == "" {
		return nil, fmt.Errorf("token_label is required")
	}
	if len(cfg.KeyID) == 0 && cfg.KeyLabel == "" {
		return nil, fmt.Errorf("at least one of key_id or key_label is required")
	}

	mod, err := Load(cfg.ModulePath)
	if err != nil {
		return nil, err
	}

	rv := mod.C_Initialize(0)
	if rv != CKR_OK && rv != 0x00000191 { // CKR_CRYPTOKI_ALREADY_INITIALIZED
		mod.Close()
		return nil, fmt.Errorf("C_Initialize failed: 0x%x", rv)
	}

	slot, err := mod.FindSlotByLabel(cfg.TokenLabel)
	if err != nil {
		mod.Close()
		return nil, fmt.Errorf("find slot: %w", err)
	}

	var session CK_ULONG
	rv = mod.C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, 0, 0, &session)
	if rv != CKR_OK {
		mod.Close()
		return nil, fmt.Errorf("C_OpenSession failed: 0x%x", rv)
	}

	if cfg.PIN != "" {
		pinBytes := []byte(cfg.PIN)
		rv = mod.C_Login(session, CKU_USER, &pinBytes[0], CK_ULONG(len(pinBytes)))
		if rv != CKR_OK && rv != 0x00000100 { // CKR_USER_ALREADY_LOGGED_IN
			mod.C_CloseSession(session)
			mod.Close()
			return nil, fmt.Errorf("C_Login failed: 0x%x", rv)
		}
	}

	// Find private key.
	privKey, err := findObject(mod, session, CKO_PRIVATE_KEY, cfg.KeyID, cfg.KeyLabel)
	if err != nil {
		mod.C_CloseSession(session)
		mod.Close()
		return nil, fmt.Errorf("find private key: %w", err)
	}

	// Find corresponding public key and extract it.
	pubKeyHandle, err := findObject(mod, session, CKO_PUBLIC_KEY, cfg.KeyID, cfg.KeyLabel)
	if err != nil {
		mod.C_CloseSession(session)
		mod.Close()
		return nil, fmt.Errorf("find public key: %w", err)
	}

	pubKey, err := extractPublicKey(mod, session, pubKeyHandle)
	if err != nil {
		mod.C_CloseSession(session)
		mod.Close()
		return nil, fmt.Errorf("extract public key: %w", err)
	}

	return &Client{
		mod:     mod,
		session: session,
		privKey: privKey,
		pubKey:  pubKey,
	}, nil
}

// Signer returns a crypto.Signer backed by the PKCS#11 token.
func (c *Client) Signer() crypto.Signer {
	return &pkcs11Signer{client: c}
}

// HashFunc returns the hash function that should be used when signing with
// this key.  The caller (e.g. the agent plugin) must hash the data with this
// algorithm and pass the result to Signer().Sign().
func (c *Client) HashFunc() crypto.Hash {
	if ecKey, ok := c.pubKey.(*ecdsa.PublicKey); ok {
		switch ecKey.Curve {
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		}
	}
	return crypto.SHA256
}

// Close releases the PKCS#11 session and module.
func (c *Client) Close() error {
	if c.mod != nil {
		c.mod.C_Logout(c.session)
		c.mod.C_CloseSession(c.session)
		c.mod.Close()
		c.mod = nil
	}
	return nil
}

var _ io.Closer = (*Client)(nil)

// pkcs11Signer implements crypto.Signer using PKCS#11 C_Sign.
type pkcs11Signer struct {
	client *Client
}

func (s *pkcs11Signer) Public() crypto.PublicKey {
	return s.client.pubKey
}

func (s *pkcs11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, fmt.Errorf("opts must not be nil")
	}

	switch s.client.pubKey.(type) {
	case *ecdsa.PublicKey:
		switch opts.HashFunc() {
		case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		default:
			return nil, fmt.Errorf("unsupported hash function %v for ECDSA", opts.HashFunc())
		}
		return s.signECDSA(digest)
	case *rsa.PublicKey:
		switch opts.HashFunc() {
		case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		default:
			return nil, fmt.Errorf("unsupported hash function %v for RSA", opts.HashFunc())
		}
		return s.signRSAPKCS1v15(digest, opts.HashFunc())
	default:
		return nil, fmt.Errorf("unsupported key type %T", s.client.pubKey)
	}
}

// signECDSA signs a pre-hashed digest using CKM_ECDSA and returns the
// signature in ASN.1 DER format.
func (s *pkcs11Signer) signECDSA(digest []byte) ([]byte, error) {
	c := s.client

	mech := Mechanism{Mechanism: CKM_ECDSA}
	rv := c.mod.C_SignInit(c.session, &mech, c.privKey)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_SignInit failed: 0x%x", rv)
	}

	var sigLen CK_ULONG
	rv = c.mod.C_Sign(c.session, &digest[0], CK_ULONG(len(digest)), nil, &sigLen)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_Sign (length query) failed: 0x%x", rv)
	}

	sig := make([]byte, sigLen)
	rv = c.mod.C_Sign(c.session, &digest[0], CK_ULONG(len(digest)), &sig[0], &sigLen)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_Sign failed: 0x%x", rv)
	}
	sig = sig[:sigLen]

	// CKM_ECDSA returns raw r||s; convert to ASN.1 DER.
	return rawECDSAToASN1(sig)
}

// signRSAPKCS1v15 signs a pre-hashed digest using CKM_RSA_PKCS (PKCS#1 v1.5).
// The DigestInfo structure is prepended to the digest before passing to the token.
func (s *pkcs11Signer) signRSAPKCS1v15(digest []byte, h crypto.Hash) ([]byte, error) {
	c := s.client

	digestInfo, err := buildDigestInfo(h, digest)
	if err != nil {
		return nil, err
	}

	mech := Mechanism{Mechanism: CKM_RSA_PKCS}
	rv := c.mod.C_SignInit(c.session, &mech, c.privKey)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_SignInit failed: 0x%x", rv)
	}

	var sigLen CK_ULONG
	rv = c.mod.C_Sign(c.session, &digestInfo[0], CK_ULONG(len(digestInfo)), nil, &sigLen)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_Sign (length query) failed: 0x%x", rv)
	}

	sig := make([]byte, sigLen)
	rv = c.mod.C_Sign(c.session, &digestInfo[0], CK_ULONG(len(digestInfo)), &sig[0], &sigLen)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_Sign failed: 0x%x", rv)
	}
	return sig[:sigLen], nil
}

// buildDigestInfo constructs the DER-encoded DigestInfo structure required by
// CKM_RSA_PKCS (PKCS#1 v1.5).
func buildDigestInfo(h crypto.Hash, digest []byte) ([]byte, error) {
	var prefix []byte
	switch h {
	case crypto.SHA256:
		prefix = digestInfoPrefixSHA256
	case crypto.SHA384:
		prefix = digestInfoPrefixSHA384
	case crypto.SHA512:
		prefix = digestInfoPrefixSHA512
	default:
		return nil, fmt.Errorf("unsupported hash function %v for RSA PKCS#1 v1.5", h)
	}
	return append(append([]byte(nil), prefix...), digest...), nil
}

// rawECDSAToASN1 converts a raw ECDSA signature (r||s) to ASN.1 DER format.
func rawECDSAToASN1(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("raw ECDSA signature has odd length %d", len(raw))
	}
	half := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])
	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}

// findObject locates a single PKCS#11 object matching the given class, key ID,
// and/or label.
func findObject(mod *Module, session CK_ULONG, class CK_ULONG, keyID []byte, keyLabel string) (CK_ULONG, error) {
	attrs, keepAlive := buildFindTemplate(class, keyID, keyLabel)
	// KeepAlive must be deferred so it runs after all C calls that use the
	// pointers embedded in attrs.  Placing it before the C calls would allow
	// the GC to collect the underlying data while C_FindObjectsInit is running.
	defer runtime.KeepAlive(keepAlive)

	rv := mod.C_FindObjectsInit(session, &attrs[0], CK_ULONG(len(attrs)))
	if rv != CKR_OK {
		return 0, fmt.Errorf("C_FindObjectsInit failed: 0x%x", rv)
	}
	defer mod.C_FindObjectsFinal(session)

	var obj CK_ULONG
	var count CK_ULONG
	rv = mod.C_FindObjects(session, &obj, 1, &count)
	if rv != CKR_OK {
		return 0, fmt.Errorf("C_FindObjects failed: 0x%x", rv)
	}
	if count == 0 {
		return 0, fmt.Errorf("object not found (class=0x%x, key_id=%x, key_label=%q)", class, keyID, keyLabel)
	}
	return obj, nil
}

// readAttribute reads a single PKCS#11 attribute from an object into a byte
// slice.  It performs two calls: the first to discover the length, the second
// to retrieve the value.
func readAttribute(mod *Module, session, obj CK_ULONG, attrType CK_ULONG) ([]byte, error) {
	// First call: pValue=nil, ulValueLen=0 → DLL fills in ulValueLen with the byte size.
	lenAttr := Attribute{Type: attrType}
	rv := mod.C_GetAttributeValue(session, obj, &lenAttr, 1)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_GetAttributeValue (length) for type 0x%x failed: 0x%x", attrType, rv)
	}
	buf := make([]byte, lenAttr.ValueLen)
	// Second call: pValue=&buf[0], ulValueLen=len → DLL fills in the value.
	valAttr := newAttr(attrType, unsafe.Pointer(&buf[0]), lenAttr.ValueLen)
	rv = mod.C_GetAttributeValue(session, obj, &valAttr, 1)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_GetAttributeValue for type 0x%x failed: 0x%x", attrType, rv)
	}
	return buf[:valAttr.ValueLen], nil
}

// extractPublicKey reads the key type from a PKCS#11 public key object and
// delegates to the appropriate extraction function.
func extractPublicKey(mod *Module, session, obj CK_ULONG) (crypto.PublicKey, error) {
	keyTypeBytes, err := readAttribute(mod, session, obj, CKA_KEY_TYPE)
	if err != nil {
		return nil, fmt.Errorf("read key type: %w", err)
	}

	var keyType CK_ULONG
	switch len(keyTypeBytes) {
	case 4:
		keyType = CK_ULONG(binary.LittleEndian.Uint32(keyTypeBytes))
	case 8:
		keyType = CK_ULONG(binary.LittleEndian.Uint64(keyTypeBytes))
	default:
		return nil, fmt.Errorf("unexpected key type attribute length: %d", len(keyTypeBytes))
	}

	switch keyType {
	case CKK_EC:
		return extractECPublicKey(mod, session, obj)
	case CKK_RSA:
		return extractRSAPublicKey(mod, session, obj)
	default:
		return nil, fmt.Errorf("unsupported key type: 0x%x", keyType)
	}
}

// extractECPublicKey reads CKA_EC_PARAMS (curve OID) and CKA_EC_POINT from a
// public key object and returns an *ecdsa.PublicKey.  P-256, P-384, and P-521
// are supported.
func extractECPublicKey(mod *Module, session, obj CK_ULONG) (*ecdsa.PublicKey, error) {
	// Read the curve OID from CKA_EC_PARAMS.
	ecParamsBytes, err := readAttribute(mod, session, obj, CKA_EC_PARAMS)
	if err != nil {
		return nil, fmt.Errorf("read EC params: %w", err)
	}
	curve, err := oidToCurve(ecParamsBytes)
	if err != nil {
		return nil, err
	}

	// Read the public point from CKA_EC_POINT.
	ecPointBytes, err := readAttribute(mod, session, obj, CKA_EC_POINT)
	if err != nil {
		return nil, fmt.Errorf("read EC point: %w", err)
	}

	// The EC_POINT is DER-encoded as an OCTET STRING wrapping the
	// uncompressed point (04 || X || Y).
	var pointBytes []byte
	if _, err := asn1.Unmarshal(ecPointBytes, &pointBytes); err != nil {
		// Some tokens return the raw point without ASN.1 wrapping.
		pointBytes = ecPointBytes
	}

	// Validate the point is on the curve using the ecdh package.
	var ecdhErr error
	switch curve {
	case elliptic.P256():
		_, ecdhErr = ecdh.P256().NewPublicKey(pointBytes)
	case elliptic.P384():
		_, ecdhErr = ecdh.P384().NewPublicKey(pointBytes)
	case elliptic.P521():
		_, ecdhErr = ecdh.P521().NewPublicKey(pointBytes)
	}
	if ecdhErr != nil {
		return nil, fmt.Errorf("invalid EC point for %s: %w", curve.Params().Name, ecdhErr)
	}

	// Uncompressed point: 0x04 || X (coordSize bytes) || Y (coordSize bytes).
	coordSize := (curve.Params().BitSize + 7) / 8
	expected := 2*coordSize + 1
	if len(pointBytes) != expected || pointBytes[0] != 0x04 {
		return nil, fmt.Errorf("expected %d-byte uncompressed %s point, got %d bytes",
			expected, curve.Params().Name, len(pointBytes))
	}
	x := new(big.Int).SetBytes(pointBytes[1 : 1+coordSize])
	y := new(big.Int).SetBytes(pointBytes[1+coordSize:])
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// extractRSAPublicKey reads CKA_MODULUS and CKA_PUBLIC_EXPONENT from a public
// key object and returns an *rsa.PublicKey.
func extractRSAPublicKey(mod *Module, session, obj CK_ULONG) (*rsa.PublicKey, error) {
	modulusBytes, err := readAttribute(mod, session, obj, CKA_MODULUS)
	if err != nil {
		return nil, fmt.Errorf("read RSA modulus: %w", err)
	}
	exponentBytes, err := readAttribute(mod, session, obj, CKA_PUBLIC_EXPONENT)
	if err != nil {
		return nil, fmt.Errorf("read RSA public exponent: %w", err)
	}

	n := new(big.Int).SetBytes(modulusBytes)
	e := new(big.Int).SetBytes(exponentBytes)
	if !e.IsInt64() || e.Int64() > (1<<31-1) {
		return nil, fmt.Errorf("RSA public exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// oidToCurve maps a DER-encoded EC curve OID to an elliptic.Curve.
func oidToCurve(ecParams []byte) (elliptic.Curve, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ecParams, &oid); err != nil {
		return nil, fmt.Errorf("parse EC curve OID: %w", err)
	}
	switch {
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256(), nil
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384(), nil
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve OID: %v", oid)
	}
}
