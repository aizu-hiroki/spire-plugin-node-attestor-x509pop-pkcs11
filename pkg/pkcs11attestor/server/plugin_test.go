package server_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11/pkg/pkcs11attestor/server"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testPKI holds the CA and leaf certificate/key for tests.
type testPKI struct {
	caKey       *ecdsa.PrivateKey
	caCertDER   []byte
	caCertPEM   []byte
	leafKey     *ecdsa.PrivateKey
	leafCertDER []byte
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

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
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caCertDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	return &testPKI{
		caKey:       caKey,
		caCertDER:   caCertDER,
		caCertPEM:   caCertPEM,
		leafKey:     leafKey,
		leafCertDER: leafCertDER,
	}
}

func (pki *testPKI) writeCABundle(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pki.caCertPEM, 0o644); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	return p
}

func configurePlugin(t *testing.T, plug *server.Plugin, caBundlePath string) {
	t.Helper()
	// Convert Windows backslashes to forward slashes for HCL compatibility.
	caBundlePath = strings.ReplaceAll(caBundlePath, `\`, `/`)
	_, err := plug.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: `ca_bundle_path = "` + caBundlePath + `"` + "\n" + `allow_reattestation = true`,
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "example.org",
		},
	})
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}
}

type attestationPayload struct {
	Certificates [][]byte `json:"certificates"`
}

type challengeResponseJSON struct {
	Signature []byte `json:"signature"`
}

// buildAttestStream creates a FakeAttestStream that simulates the agent sending
// the certificate payload and then responding to the challenge with a signature.
func buildAttestStream(t *testing.T, leafCertDER []byte, signer crypto.Signer) *server.FakeAttestStream {
	t.Helper()

	payload, err := json.Marshal(&attestationPayload{
		Certificates: [][]byte{leafCertDER},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	// The stream delivers the payload first.  After the server sends a
	// challenge we need to supply the challenge response.  Because the
	// FakeAttestStream is synchronous we pre-compute the response by hooking
	// into Send.
	stream := &challengeSigningStream{
		FakeAttestStream: server.FakeAttestStream{
			Requests: []*nodeattestorv1.AttestRequest{
				{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}},
			},
		},
		signer: signer,
		t:      t,
	}
	return &stream.FakeAttestStream
}

// challengeSigningStream wraps FakeAttestStream to automatically sign any
// challenge the server sends and append the response to the request queue.
type challengeSigningStream struct {
	server.FakeAttestStream
	signer crypto.Signer
	t      *testing.T
}

func (s *challengeSigningStream) Send(resp *nodeattestorv1.AttestResponse) error {
	// If the server sent a challenge, create the signed response.
	if challenge := resp.GetChallenge(); len(challenge) > 0 {
		digest := sha256.Sum256(challenge)
		sig, err := s.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			s.t.Fatalf("sign challenge: %v", err)
		}
		respJSON, _ := json.Marshal(&challengeResponseJSON{Signature: sig})
		s.FakeAttestStream.Requests = append(s.FakeAttestStream.Requests,
			&nodeattestorv1.AttestRequest{
				Request: &nodeattestorv1.AttestRequest_ChallengeResponse{
					ChallengeResponse: respJSON,
				},
			})
	}
	return s.FakeAttestStream.Send(resp)
}

func (s *challengeSigningStream) Recv() (*nodeattestorv1.AttestRequest, error) {
	return s.FakeAttestStream.Recv()
}

func (s *challengeSigningStream) Context() context.Context {
	return s.FakeAttestStream.Context()
}

// --- Tests ---

func TestAttest_Success(t *testing.T) {
	pki := newTestPKI(t)
	plug := server.New()
	configurePlugin(t, plug, pki.writeCABundle(t))

	stream := &challengeSigningStream{
		FakeAttestStream: server.FakeAttestStream{
			Requests: []*nodeattestorv1.AttestRequest{
				{Request: &nodeattestorv1.AttestRequest_Payload{
					Payload: mustMarshal(t, &attestationPayload{
						Certificates: [][]byte{pki.leafCertDER},
					}),
				}},
			},
		},
		signer: pki.leafKey,
		t:      t,
	}

	if err := plug.Attest(stream); err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Find the AgentAttributes response (skip the challenge response).
	var attrs *nodeattestorv1.AgentAttributes
	for _, resp := range stream.FakeAttestStream.Responses {
		if a := resp.GetAgentAttributes(); a != nil {
			attrs = a
			break
		}
	}
	if attrs == nil {
		t.Fatal("expected AgentAttributes in responses")
	}

	// Verify SPIFFE ID contains the certificate fingerprint.
	leafCert, _ := x509.ParseCertificate(pki.leafCertDER)
	wantID := server.AgentID("example.org", leafCert)
	if attrs.SpiffeId != wantID {
		t.Errorf("SpiffeId = %q, want %q", attrs.SpiffeId, wantID)
	}

	// Verify selectors.
	selectorSet := make(map[string]bool)
	for _, v := range attrs.SelectorValues {
		selectorSet[v] = true
	}
	if !selectorSet["subject:cn:test-node"] {
		t.Error("missing selector subject:cn:test-node")
	}
	if !selectorSet["serial:2"] {
		t.Error("missing selector serial:2")
	}
}

func TestAttest_InvalidSignature(t *testing.T) {
	pki := newTestPKI(t)
	plug := server.New()
	configurePlugin(t, plug, pki.writeCABundle(t))

	// Use a different key to sign the challenge (wrong key).
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	stream := &challengeSigningStream{
		FakeAttestStream: server.FakeAttestStream{
			Requests: []*nodeattestorv1.AttestRequest{
				{Request: &nodeattestorv1.AttestRequest_Payload{
					Payload: mustMarshal(t, &attestationPayload{
						Certificates: [][]byte{pki.leafCertDER},
					}),
				}},
			},
		},
		signer: wrongKey,
		t:      t,
	}

	err := plug.Attest(stream)
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", err)
	}
}

func TestAttest_UntrustedCert(t *testing.T) {
	pki := newTestPKI(t)
	plug := server.New()

	// Configure with a different CA (not the one that signed the leaf).
	otherPKI := newTestPKI(t)
	configurePlugin(t, plug, otherPKI.writeCABundle(t))

	stream := &challengeSigningStream{
		FakeAttestStream: server.FakeAttestStream{
			Requests: []*nodeattestorv1.AttestRequest{
				{Request: &nodeattestorv1.AttestRequest_Payload{
					Payload: mustMarshal(t, &attestationPayload{
						Certificates: [][]byte{pki.leafCertDER},
					}),
				}},
			},
		},
		signer: pki.leafKey,
		t:      t,
	}

	err := plug.Attest(stream)
	if err == nil {
		t.Fatal("expected error for untrusted certificate, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", err)
	}
}

func TestAttest_EmptyPayload(t *testing.T) {
	plug := server.New()
	stream := &server.FakeAttestStream{
		Requests: []*nodeattestorv1.AttestRequest{
			{Request: &nodeattestorv1.AttestRequest_Payload{Payload: nil}},
		},
	}
	err := plug.Attest(stream)
	if err == nil {
		t.Fatal("expected error for empty payload, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestAttest_NoCertificates(t *testing.T) {
	pki := newTestPKI(t)
	plug := server.New()
	configurePlugin(t, plug, pki.writeCABundle(t))

	stream := &server.FakeAttestStream{
		Requests: []*nodeattestorv1.AttestRequest{
			{Request: &nodeattestorv1.AttestRequest_Payload{
				Payload: mustMarshal(t, &attestationPayload{Certificates: nil}),
			}},
		},
	}
	err := plug.Attest(stream)
	if err == nil {
		t.Fatal("expected error for no certificates, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestConfigure_MissingCABundle(t *testing.T) {
	plug := server.New()
	_, err := plug.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration:  ``,
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
	})
	if err == nil {
		t.Fatal("expected error for missing ca_bundle_path")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
