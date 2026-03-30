//go:build yubikey

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// SetupYubiKey provisions YubiKey PIV slot 9a for testing and returns a TestEnv
// ready for use with NewClient or the agent plugin.
//
// The function:
//   - Skips (t.Skip) if no YubiKey is detected or required tools are absent.
//   - Generates a fresh P-256 key on-device in slot 9a.
//   - Generates a software CA and a leaf cert signed by it, then imports the
//     leaf cert into slot 9a.
//   - Registers a t.Cleanup that removes the leaf cert from slot 9a (best-effort).
//
// Environment variables:
//
//	YUBIKEY_PIN            — PIN for the YubiKey PIV application (default: "123456").
//	YUBIKEY_MANAGEMENT_KEY — PIV management key in hex (default: YubiKey factory default).
//
// WARNING: Running this function overwrites PIV slot 9a on the connected
// YubiKey. Do not use on a YubiKey that holds production credentials.
//
// Requires ykman (>= 4.x) in PATH.
func SetupYubiKey(t *testing.T) *TestEnv {
	t.Helper()

	modulePath := findYubiKeyLib(t)

	if _, err := exec.LookPath("ykman"); err != nil {
		t.Skip("ykman not in PATH; skipping YubiKey test")
	}

	// Verify a YubiKey is actually connected.
	out, err := exec.Command("ykman", "list").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Skip("no YubiKey detected (ykman list returned empty); skipping YubiKey test")
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		pin = "123456"
	}

	// Default management key is the YubiKey factory default (3DES).
	mgmtKey := os.Getenv("YUBIKEY_MANAGEMENT_KEY")
	if mgmtKey == "" {
		mgmtKey = "010203040506070801020304050607080102030405060708"
	}

	tmpDir := t.TempDir()

	// Generate a fresh P-256 key on slot 9a.
	pubKeyPath := filepath.Join(tmpDir, "pubkey.pem")
	genOut, err := exec.Command(
		"ykman", "piv", "keys", "generate",
		"--management-key", mgmtKey,
		"--pin-policy", "once",
		"--touch-policy", "never",
		"--algorithm", "ECCP256",
		"9a",
		pubKeyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("ykman piv keys generate failed: %v\n%s", err, genOut)
	}

	// Parse the public key written by ykman.
	pubKeyPEM, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("read pubkey PEM: %v", err)
	}
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		t.Fatalf("no PEM block in pubkey file")
	}
	pubKeyIface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	ecPub, ok := pubKeyIface.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pubKeyIface)
	}

	// Generate software CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Sign a leaf cert using the YubiKey's public key.
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, ecPub, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	// Write leaf cert PEM and import it into slot 9a.
	certPEMPath := filepath.Join(tmpDir, "leaf.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})
	if err := os.WriteFile(certPEMPath, certPEM, 0o644); err != nil {
		t.Fatalf("write leaf cert PEM: %v", err)
	}
	importOut, err := exec.Command(
		"ykman", "piv", "certificates", "import",
		"--management-key", mgmtKey,
		"--pin", pin,
		"9a",
		certPEMPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("ykman piv certificates import failed: %v\n%s", err, importOut)
	}

	// Discover the token label dynamically (includes serial number).
	tokenLabel, err := discoverTokenLabel(modulePath)
	if err != nil {
		t.Fatalf("discover YubiKey token label: %v\n"+
			"Ensure libykcs11 >= 2.3.0 is installed.", err)
	}

	// Preflight check: verify that NewClient can open the session and find the key.
	// This catches ykcs11 version issues (e.g. missing CKO_PUBLIC_KEY) early.
	cfg := &Config{
		ModulePath: modulePath,
		TokenLabel: tokenLabel,
		PIN:        pin,
		KeyID:      []byte{0x01},
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient preflight failed: %v\n"+
			"Check that libykcs11 >= 2.3.0 is installed and the key is in slot 9a.", err)
	}
	client.Close()

	t.Cleanup(func() {
		// Best-effort: delete the test certificate from slot 9a.
		exec.Command("ykman", "piv", "certificates", "delete", "--force", "9a").Run() //nolint:errcheck
	})

	return &TestEnv{
		ModulePath:  modulePath,
		TokenLabel:  tokenLabel,
		PIN:         pin,
		KeyID:       []byte{0x01},
		KeyLabel:    "",
		CACert:      caCert,
		CACertDER:   caCertDER,
		LeafCert:    leafCert,
		LeafCertDER: leafCertDER,
		LeafKey:     nil, // private key never leaves the YubiKey
	}
}

// findYubiKeyLib returns the path to the ykcs11 shared library for the current
// platform. If no candidate path exists, the test is skipped.
func findYubiKeyLib(t *testing.T) string {
	t.Helper()
	candidates := yubikeyLibCandidates()
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skipf("ykcs11 library not found at expected paths: %v", candidates)
	return ""
}

// yubikeyLibCandidates returns OS-specific candidate paths for libykcs11.
func yubikeyLibCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/opt/homebrew/lib/libykcs11.dylib", // Apple Silicon
			"/usr/local/lib/libykcs11.dylib",    // Intel
		}
	case "windows":
		return []string{
			`C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll`,
			`C:\Program Files (x86)\Yubico\Yubico PIV Tool\bin\libykcs11.dll`,
		}
	default: // linux
		return []string{
			"/usr/lib/x86_64-linux-gnu/libykcs11.so",
			"/usr/lib/libykcs11.so",
			"/usr/local/lib/libykcs11.so",
			"/usr/lib64/libykcs11.so",
		}
	}
}

// discoverTokenLabel loads the ykcs11 module via PKCS#11 and returns the label
// of the first token whose label has the prefix "YubiKey PIV".
//
// This avoids shelling out to external tools and reuses the existing pure-Go
// PKCS#11 infrastructure.
func discoverTokenLabel(modulePath string) (string, error) {
	mod, err := Load(modulePath)
	if err != nil {
		return "", fmt.Errorf("load module: %w", err)
	}
	defer mod.Close()

	const ckrAlreadyInitialized CK_ULONG = 0x00000191
	rv := mod.C_Initialize(0)
	if rv != CKR_OK && rv != ckrAlreadyInitialized {
		return "", fmt.Errorf("C_Initialize: 0x%x", rv)
	}

	slots, err := mod.GetSlotList()
	if err != nil {
		return "", fmt.Errorf("GetSlotList: %w", err)
	}

	for _, slot := range slots {
		info, err := mod.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.HasPrefix(info.Label, "YubiKey PIV") {
			return info.Label, nil
		}
	}

	return "", fmt.Errorf("no YubiKey PIV token found in slot list (is the YubiKey connected?)")
}
