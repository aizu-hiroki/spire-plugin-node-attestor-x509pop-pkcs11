package agent_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkcs11test "github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11/internal/pkcs11"
	"github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11/pkg/pkcs11attestor/agent"
	nodeattestoragentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

// fakeAidAttestationStream simulates the agent-side gRPC stream.
type fakeAidAttestationStream struct {
	nodeattestoragentv1.NodeAttestor_AidAttestationServer
	sent      []*nodeattestoragentv1.PayloadOrChallengeResponse
	challenge []byte // nonce to send as challenge
	recvIdx   int
}

func (s *fakeAidAttestationStream) Send(msg *nodeattestoragentv1.PayloadOrChallengeResponse) error {
	s.sent = append(s.sent, msg)
	return nil
}

func (s *fakeAidAttestationStream) Recv() (*nodeattestoragentv1.Challenge, error) {
	if s.recvIdx > 0 {
		// After the first recv, the stream is done.
		return nil, context.Canceled
	}
	s.recvIdx++
	return &nodeattestoragentv1.Challenge{Challenge: s.challenge}, nil
}

func (s *fakeAidAttestationStream) Context() context.Context {
	return context.Background()
}

func TestAidAttestation_FullFlow(t *testing.T) {
	env := pkcs11test.SetupSoftHSM(t)

	// Write the leaf certificate as PEM.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.LeafCertDER})
	certPath := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	plug := agent.New()
	t.Cleanup(plug.Close)
	hclConfig := `
		module_path      = "` + strings.ReplaceAll(env.ModulePath, `\`, `/`) + `"
		token_label      = "` + env.TokenLabel + `"
		pin              = "` + env.PIN + `"
		key_id           = "01"
		key_label        = "` + env.KeyLabel + `"
		certificate_path = "` + strings.ReplaceAll(certPath, `\`, `/`) + `"
	`
	_, err := plug.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hclConfig,
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	nonce := []byte("test-challenge-nonce-1234567890ab")
	stream := &fakeAidAttestationStream{challenge: nonce}

	if err := plug.AidAttestation(stream); err != nil {
		t.Fatalf("AidAttestation failed: %v", err)
	}

	// Should have sent 2 messages: payload + challenge response.
	if len(stream.sent) != 2 {
		t.Fatalf("expected 2 sent messages, got %d", len(stream.sent))
	}

	// Verify payload contains the certificate.
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
	if len(payload.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(payload.Certificates))
	}
	leaf, err := x509.ParseCertificate(payload.Certificates[0])
	if err != nil {
		t.Fatalf("parse certificate from payload: %v", err)
	}
	if leaf.Subject.CommonName != "test-node" {
		t.Errorf("leaf CN = %q, want %q", leaf.Subject.CommonName, "test-node")
	}

	// Verify challenge response signature.
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
	pub := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pub, digest[:], resp.Signature) {
		t.Fatal("challenge response signature verification failed")
	}
}

func TestConfigure_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		hcl  string
	}{
		{"missing module_path", `token_label = "t"
certificate_path = "/x"
key_id = "01"`},
		{"missing token_label", `module_path = "/x"
certificate_path = "/x"
key_id = "01"`},
		{"missing certificate_path", `module_path = "/x"
token_label = "t"
key_id = "01"`},
		{"missing key_id and key_label", `module_path = "/x"
token_label = "t"
certificate_path = "/x"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plug := agent.New()
			_, err := plug.Configure(context.Background(), &configv1.ConfigureRequest{
				HclConfiguration: tt.hcl,
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// Verify that Sign uses SHA256.
func TestAidAttestation_SignatureAlgorithm(t *testing.T) {
	env := pkcs11test.SetupSoftHSM(t)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.LeafCertDER})
	certPath := filepath.Join(t.TempDir(), "leaf.pem")
	os.WriteFile(certPath, certPEM, 0o644)

	plug := agent.New()
	t.Cleanup(plug.Close)
	_, err := plug.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `
			module_path      = "` + strings.ReplaceAll(env.ModulePath, `\`, `/`) + `"
			token_label      = "` + env.TokenLabel + `"
			pin              = "` + env.PIN + `"
			key_id           = "01"
			certificate_path = "` + strings.ReplaceAll(certPath, `\`, `/`) + `"
		`,
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	nonce := []byte("another-test-nonce-for-algorithm")
	stream := &fakeAidAttestationStream{challenge: nonce}

	if err := plug.AidAttestation(stream); err != nil {
		t.Fatalf("AidAttestation failed: %v", err)
	}

	// Extract and verify the signature was computed over SHA-256(nonce).
	var resp struct{ Signature []byte }
	json.Unmarshal(stream.sent[1].GetChallengeResponse(), &resp)

	digest := sha256.Sum256(nonce)
	_ = crypto.SHA256 // algorithm marker
	if !ecdsa.VerifyASN1(&env.LeafKey.PublicKey, digest[:], resp.Signature) {
		t.Fatal("signature is not a valid SHA-256 ECDSA signature")
	}
}
