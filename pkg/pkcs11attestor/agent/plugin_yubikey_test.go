//go:build yubikey

package agent_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkcs11test "github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11/internal/pkcs11"
	"github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11/pkg/pkcs11attestor/agent"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

// TestAidAttestation_YubiKey_FullFlow exercises the complete attestation
// protocol using a real YubiKey 5 series PIV device on slot 9a.
//
// Prerequisites (see docs/hardware_setup.md — YubiKey 5 Series section):
//   - YubiKey 5 series connected via USB
//   - ykman (yubico-yubikey-manager >= 4.x) in PATH
//   - libykcs11 >= 2.3.0 installed
//   - YUBIKEY_PIN env var set (default: 123456)
//
// WARNING: This test overwrites PIV slot 9a on the connected YubiKey.
// Do not run on a YubiKey that holds production credentials.
//
// Run with:
//
//	make test-yubikey
//	# or
//	go test -tags yubikey -v -count=1 ./pkg/pkcs11attestor/agent/
func TestAidAttestation_YubiKey_FullFlow(t *testing.T) {
	env := pkcs11test.SetupYubiKey(t)

	// Write the leaf certificate as PEM for the plugin's certificate_path.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.LeafCertDER})
	certPath := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	plug := agent.New()
	t.Cleanup(plug.Close)

	hclConfig := fmt.Sprintf(`
		module_path      = %q
		token_label      = %q
		pin              = %q
		key_id           = "01"
		certificate_path = %q
	`,
		strings.ReplaceAll(env.ModulePath, `\`, `/`),
		env.TokenLabel,
		env.PIN,
		strings.ReplaceAll(certPath, `\`, `/`),
	)

	_, err := plug.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hclConfig,
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	nonce := []byte("yubikey-test-challenge-nonce-12ab")
	stream := &fakeAidAttestationStream{challenge: nonce}

	if err := plug.AidAttestation(stream); err != nil {
		t.Fatalf("AidAttestation failed: %v", err)
	}

	if len(stream.sent) != 2 {
		t.Fatalf("expected 2 sent messages, got %d", len(stream.sent))
	}

	// Verify payload contains the leaf certificate.
	payloadBytes := stream.sent[0].GetPayload()
	if payloadBytes == nil {
		t.Fatal("first message should be payload")
	}
	var payload struct {
		Certificates [][]byte `json:"certificates"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if len(payload.Certificates) == 0 {
		t.Fatal("expected at least one certificate in payload")
	}
	leaf, err := x509.ParseCertificate(payload.Certificates[0])
	if err != nil {
		t.Fatalf("parse certificate from payload: %v", err)
	}
	if leaf.Subject.CommonName != "test-node" {
		t.Errorf("leaf CN = %q, want %q", leaf.Subject.CommonName, "test-node")
	}

	// Verify challenge response signature.
	// Note: env.LeafKey is nil for YubiKey (private key never exported).
	// We use the public key from the certificate in the payload instead.
	respBytes := stream.sent[1].GetChallengeResponse()
	if respBytes == nil {
		t.Fatal("second message should be challenge response")
	}
	var resp struct {
		Signature []byte `json:"signature"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal challenge response: %v", err)
	}

	digest := sha256.Sum256(nonce)
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey in leaf cert, got %T", leaf.PublicKey)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], resp.Signature) {
		t.Fatal("challenge response signature verification failed")
	}
}
