package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

func TestNewClient_SignAndVerify(t *testing.T) {
	env := SetupSoftHSM(t)

	client, err := NewClient(&Config{
		ModulePath: env.ModulePath,
		TokenLabel: env.TokenLabel,
		PIN:        env.PIN,
		KeyID:      env.KeyID,
		KeyLabel:   env.KeyLabel,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	signer := client.Signer()
	if signer == nil {
		t.Fatal("Signer() returned nil")
	}

	// Verify the public key matches the leaf key.
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", signer.Public())
	}
	if !pub.Equal(&env.LeafKey.PublicKey) {
		t.Fatal("public key from PKCS#11 does not match imported key")
	}

	// Sign some data and verify the signature.
	data := []byte("challenge-nonce-for-testing")
	digest := sha256.Sum256(data)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !ecdsa.VerifyASN1(&env.LeafKey.PublicKey, digest[:], sig) {
		t.Fatal("signature verification failed")
	}
}

func TestNewClient_KeyNotFound(t *testing.T) {
	env := SetupSoftHSM(t)

	_, err := NewClient(&Config{
		ModulePath: env.ModulePath,
		TokenLabel: env.TokenLabel,
		PIN:        env.PIN,
		KeyID:      []byte{0xff},
		KeyLabel:   "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for non-existent key, got nil")
	}
}

func TestLoadCertificate(t *testing.T) {
	env := SetupSoftHSM(t)

	if !env.CertImportedToToken {
		t.Skip("pkcs11-tool not in PATH; cert not imported to token — skipping")
	}

	client, err := NewClient(&Config{
		ModulePath: env.ModulePath,
		TokenLabel: env.TokenLabel,
		PIN:        env.PIN,
		KeyID:      env.KeyID,
		KeyLabel:   env.KeyLabel,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Fallback path: certID=nil, certLabel="" → uses keyID/keyLabel.
	der, err := client.LoadCertificate(nil, "")
	if err != nil {
		t.Fatalf("LoadCertificate (fallback): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse DER from token: %v", err)
	}
	if cert.Subject.CommonName != "test-node" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "test-node")
	}

	// Explicit certID path — must return identical bytes.
	der2, err := client.LoadCertificate(env.KeyID, "")
	if err != nil {
		t.Fatalf("LoadCertificate (explicit ID): %v", err)
	}
	if !bytes.Equal(der, der2) {
		t.Error("explicit certID lookup returned different DER than fallback")
	}
}

func TestLoadCertificate_NotFound(t *testing.T) {
	env := SetupSoftHSM(t)

	client, err := NewClient(&Config{
		ModulePath: env.ModulePath,
		TokenLabel: env.TokenLabel,
		PIN:        env.PIN,
		KeyID:      env.KeyID,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	_, err = client.LoadCertificate([]byte{0xff, 0xfe}, "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent cert, got nil")
	}
}

func TestNewClient_MissingConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
	}{
		{"missing module_path", &Config{TokenLabel: "t", KeyID: []byte{1}}},
		{"missing token_label", &Config{ModulePath: "/x", KeyID: []byte{1}}},
		{"missing key_id and key_label", &Config{ModulePath: "/x", TokenLabel: "t"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestNewClient_PublicKeyOnCurve(t *testing.T) {
	env := SetupSoftHSM(t)

	client, err := NewClient(&Config{
		ModulePath: env.ModulePath,
		TokenLabel: env.TokenLabel,
		PIN:        env.PIN,
		KeyID:      env.KeyID,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	pub, ok := client.Signer().Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", client.Signer().Public())
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve, got %v", pub.Curve.Params().Name)
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		t.Fatal("public key is not on P-256 curve")
	}
}
