package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestEnv holds the resources created for a PKCS#11 test scenario.
type TestEnv struct {
	// ModulePath is the resolved path to the SoftHSM2 library.
	ModulePath string

	// TokenLabel used for the initialised token.
	TokenLabel string

	// PIN for the token.
	PIN string

	// KeyID assigned to the imported key.
	KeyID []byte

	// KeyLabel assigned to the imported key.
	KeyLabel string

	// CACert is the self-signed CA certificate.
	CACert    *x509.Certificate
	CACertDER []byte

	// LeafCert is the leaf certificate whose key resides in the token.
	LeafCert    *x509.Certificate
	LeafCertDER []byte

	// LeafKey is the ECDSA private key (used for generating the cert and
	// imported into the SoftHSM2 token).
	LeafKey *ecdsa.PrivateKey

	// CertImportedToToken is true when the leaf certificate was also written
	// into the token as a CKO_CERTIFICATE object (requires pkcs11-tool).
	CertImportedToToken bool
}

// SetupSoftHSM creates a temporary SoftHSM2 token, generates a self-signed CA
// and leaf certificate, and imports the leaf private key into the token using
// softhsm2-util + openssl PKCS#12 import or pkcs11-tool.
//
// Because we avoid CGo, the key import is done by writing a PKCS#8 PEM file
// and using softhsm2-util --import.
func SetupSoftHSM(t *testing.T) *TestEnv {
	t.Helper()

	modulePath := findSoftHSMLib(t)

	// Verify softhsm2-util is available.
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not in PATH; skipping PKCS#11 test")
	}

	// Create temporary directory for tokens.
	tmpDir := t.TempDir()
	tokenDir := filepath.Join(tmpDir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o755); err != nil {
		t.Fatalf("create token dir: %v", err)
	}

	confPath := filepath.Join(tmpDir, "softhsm2.conf")
	confContent := "directories.tokendir = " + tokenDir + "\nobjectstore.backend = file\n"
	if err := os.WriteFile(confPath, []byte(confContent), 0o644); err != nil {
		t.Fatalf("write softhsm2.conf: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	const tokenLabel = "test-token"
	const pin = "1234"
	const soPin = "5678"

	// Initialise the token.
	out, err := exec.Command(
		"softhsm2-util",
		"--init-token", "--free",
		"--label", tokenLabel,
		"--pin", pin,
		"--so-pin", soPin,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("softhsm2-util init-token: %v\n%s", err, out)
	}

	// Generate CA.
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

	// Generate leaf key and certificate.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	// Write leaf private key as PKCS#8 PEM for softhsm2-util --import.
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	keyPEMPath := filepath.Join(tmpDir, "leaf.key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPEMPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key PEM: %v", err)
	}

	keyID := "01"
	keyLabel := "test-key"

	// Import the private key into SoftHSM2.
	// Use --token to identify the slot by label rather than by index, which is
	// more stable across SoftHSM2 versions and environments.
	out, err = exec.Command(
		"softhsm2-util",
		"--import", keyPEMPath,
		"--token", tokenLabel,
		"--label", keyLabel,
		"--id", keyID,
		"--pin", pin,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("softhsm2-util import: %v\n%s", err, out)
	}

	// Attempt to import the leaf certificate into the token as CKO_CERTIFICATE.
	// Requires pkcs11-tool (OpenSC); skipped silently when absent so that
	// existing key-only tests still pass in environments without OpenSC.
	certImported := false
	if _, lookErr := exec.LookPath("pkcs11-tool"); lookErr == nil {
		certDERPath := filepath.Join(tmpDir, "leaf.cert.der")
		if writeErr := os.WriteFile(certDERPath, leafCertDER, 0o644); writeErr != nil {
			t.Logf("SetupSoftHSM: write cert DER: %v (cert import skipped)", writeErr)
		} else {
			importOut, importErr := exec.Command(
				"pkcs11-tool",
				"--module", modulePath,
				"--token-label", tokenLabel,
				"--login", "--pin", pin,
				"--write-object", certDERPath,
				"--type", "cert",
				"--id", keyID,
				"--label", keyLabel,
			).CombinedOutput()
			if importErr != nil {
				t.Logf("SetupSoftHSM: pkcs11-tool cert import: %v\n%s (cert import skipped)", importErr, importOut)
			} else {
				certImported = true
			}
		}
	}

	return &TestEnv{
		ModulePath:          modulePath,
		TokenLabel:          tokenLabel,
		PIN:                 pin,
		KeyID:               []byte{0x01},
		KeyLabel:            keyLabel,
		CACert:              caCert,
		CACertDER:           caCertDER,
		LeafCert:            leafCert,
		LeafCertDER:         leafCertDER,
		LeafKey:             leafKey,
		CertImportedToToken: certImported,
	}
}

func findSoftHSMLib(t *testing.T) string {
	t.Helper()
	candidates := softHSMCandidates()
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Also search versioned Cellar paths on macOS (Homebrew does not always
	// create a symlink under /usr/local/lib/softhsm/).
	for _, pattern := range softHSMGlobs() {
		matches, _ := filepath.Glob(pattern)
		if len(matches) > 0 {
			return matches[0]
		}
	}
	t.Skipf("softhsm2 library not found at expected paths: %v", candidates)
	return ""
}

func softHSMGlobs() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/usr/local/Cellar/softhsm/*/lib/softhsm/libsofthsm2.so",
			"/opt/homebrew/Cellar/softhsm/*/lib/softhsm/libsofthsm2.so",
		}
	default:
		return nil
	}
}

func softHSMCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/opt/homebrew/lib/softhsm/libsofthsm2.so",
			"/usr/local/lib/softhsm/libsofthsm2.so",
		}
	case "windows":
		return []string{
			`C:\SoftHSM2\lib\softhsm2-x64.dll`,
			`C:\SoftHSM2\lib\softhsm2.dll`,
		}
	default: // linux
		return []string{
			"/usr/lib/softhsm/libsofthsm2.so",
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
			"/usr/lib64/softhsm/libsofthsm2.so",
		}
	}
}
