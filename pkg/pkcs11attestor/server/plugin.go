// Package server implements the SPIRE server-side x509pop_pkcs11 node
// attestation plugin.
//
// This plugin runs inside the SPIRE server process.  When a SPIRE agent sends
// an attestation request the server:
//  1. Receives an X.509 certificate chain from the agent
//  2. Validates the chain against the configured CA bundle
//  3. Sends a random nonce as a challenge
//  4. Verifies the agent's signature over the nonce using the leaf certificate
//  5. Returns a SPIFFE agent ID and selectors derived from the certificate
//
// HCL configuration example (spire-server.conf):
//
//	NodeAttestor "x509pop_pkcs11" {
//	  plugin_cmd  = "/usr/local/bin/spire-plugin-pkcs11-server"
//	  plugin_data {
//	    ca_bundle_path      = "/opt/spire/conf/server/ca.pem"
//	    allow_reattestation = true
//	  }
//	}
package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const nonceLength = 32

// pluginConfig holds the parsed HCL configuration.
type pluginConfig struct {
	CABundlePath     string `hcl:"ca_bundle_path"`
	AllowReattest    bool   `hcl:"allow_reattestation"`
}

// Plugin is the server-side x509pop_pkcs11 node attestation plugin.
type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu          sync.RWMutex
	cfg         *pluginConfig
	trustDomain string
	caPool      *x509.CertPool
}

// New creates a new server-side plugin instance.
func New() *Plugin {
	return &Plugin{}
}

// Configure parses the plugin HCL and loads the CA bundle.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg := &pluginConfig{}
	if req.HclConfiguration != "" {
		if err := hcl.Decode(cfg, req.HclConfiguration); err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"failed to parse plugin configuration: %v", err)
		}
	}
	if cfg.CABundlePath == "" {
		return nil, status.Error(codes.InvalidArgument, "ca_bundle_path is required")
	}

	pool, err := loadCABundle(cfg.CABundlePath)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"failed to load CA bundle: %v", err)
	}

	p.mu.Lock()
	p.cfg = cfg
	p.trustDomain = req.CoreConfiguration.GetTrustDomain()
	p.caPool = pool
	p.mu.Unlock()

	return &configv1.ConfigureResponse{}, nil
}

// attestationPayload is the JSON structure sent by the agent as the initial
// payload.
type attestationPayload struct {
	Certificates [][]byte `json:"certificates"` // DER-encoded X.509 certificates
}

// challengeResponse is the JSON structure the agent returns after signing the
// nonce.
type challengeResponse struct {
	Signature []byte `json:"signature"`
}

// Attest validates the agent's certificate chain and proof-of-possession of
// the corresponding private key (stored on a PKCS#11 token).
func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	// --- Step 1: Receive payload ---
	req, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return status.Error(codes.InvalidArgument, "no attestation payload received")
		}
		return fmt.Errorf("failed to receive attestation request: %w", err)
	}

	payloadBytes := req.GetPayload()
	if len(payloadBytes) == 0 {
		return status.Error(codes.InvalidArgument,
			"first attestation request message must contain a payload")
	}

	var payload attestationPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return status.Errorf(codes.InvalidArgument,
			"failed to unmarshal attestation payload: %v", err)
	}
	if len(payload.Certificates) == 0 {
		return status.Error(codes.InvalidArgument,
			"attestation payload contains no certificates")
	}

	// --- Step 2: Parse and validate certificate chain ---
	leaf, err := x509.ParseCertificate(payload.Certificates[0])
	if err != nil {
		return status.Errorf(codes.InvalidArgument,
			"failed to parse leaf certificate: %v", err)
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(payload.Certificates); i++ {
		cert, err := x509.ParseCertificate(payload.Certificates[i])
		if err != nil {
			return status.Errorf(codes.InvalidArgument,
				"failed to parse intermediate certificate %d: %v", i, err)
		}
		intermediates.AddCert(cert)
	}

	p.mu.RLock()
	caPool := p.caPool
	trustDomain := p.trustDomain
	cfg := p.cfg
	p.mu.RUnlock()

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         caPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return status.Errorf(codes.PermissionDenied,
			"certificate chain verification failed: %v", err)
	}

	// --- Step 3: Send challenge ---
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return status.Errorf(codes.Internal, "failed to generate nonce: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: nonce,
		},
	}); err != nil {
		return fmt.Errorf("failed to send challenge: %w", err)
	}

	// --- Step 4: Receive challenge response ---
	challengeReq, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument,
			"failed to receive challenge response: %v", err)
	}

	var resp challengeResponse
	if err := json.Unmarshal(challengeReq.GetChallengeResponse(), &resp); err != nil {
		return status.Errorf(codes.InvalidArgument,
			"failed to unmarshal challenge response: %v", err)
	}

	// --- Step 5: Verify signature ---
	// Use the hash function matching the leaf certificate's public key type,
	// consistent with how the agent computed the digest.
	digest := digestForKey(leaf.PublicKey, nonce)
	if err := verifySignature(leaf.PublicKey, digest, resp.Signature); err != nil {
		return status.Errorf(codes.PermissionDenied,
			"challenge signature verification failed: %v", err)
	}

	// --- Step 6: Build agent ID and selectors ---
	agentID := AgentID(trustDomain, leaf)
	selectorValues := BuildSelectors(leaf)

	_ = cfg // allow_reattestation is advisory; SPIRE handles re-attestation logic.

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       agentID,
				SelectorValues: selectorValues,
				CanReattest:    cfg.AllowReattest,
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to send attestation response: %w", err)
	}

	return nil
}

// digestForKey computes the hash of data using the algorithm appropriate for
// the given public key type.  This must match the algorithm the agent uses in
// its HashFunc() method so that both sides agree on the digest.
//
//   - ECDSA P-256 / RSA → SHA-256
//   - ECDSA P-384       → SHA-384
//   - ECDSA P-521       → SHA-512
func digestForKey(pub crypto.PublicKey, data []byte) []byte {
	if ecKey, ok := pub.(*ecdsa.PublicKey); ok {
		switch ecKey.Curve {
		case elliptic.P384():
			d := sha512.Sum384(data)
			return d[:]
		case elliptic.P521():
			d := sha512.Sum512(data)
			return d[:]
		}
	}
	d := sha256.Sum256(data)
	return d[:]
}

func verifySignature(pub crypto.PublicKey, digest, sig []byte) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, sig) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sig)
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

func loadCABundle(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}

	pool := x509.NewCertPool()
	count := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate in CA bundle: %w", err)
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("no certificates found in CA bundle %s", path)
	}
	return pool, nil
}

// AgentID returns the SPIFFE agent ID for the given leaf certificate.
// Format: spiffe://<trust-domain>/spire/agent/x509pop_pkcs11/<sha1-fingerprint>
func AgentID(trustDomain string, leaf *x509.Certificate) string {
	fingerprint := sha256.Sum256(leaf.Raw)
	return fmt.Sprintf("spiffe://%s/spire/agent/x509pop_pkcs11/%x",
		trustDomain, fingerprint)
}

// BuildSelectors generates selector values from the leaf certificate.
func BuildSelectors(leaf *x509.Certificate) []string {
	var selectors []string
	add := func(key, value string) {
		if value != "" {
			selectors = append(selectors, fmt.Sprintf("%s:%s", key, value))
		}
	}
	add("subject:cn", leaf.Subject.CommonName)
	add("serial", leaf.SerialNumber.String())
	for _, uri := range leaf.URIs {
		add("uri", uri.String())
	}
	for _, dns := range leaf.DNSNames {
		add("dns", dns)
	}
	return selectors
}
