// Package agent implements the SPIRE agent-side x509pop_pkcs11 node
// attestation plugin.
//
// This plugin runs inside the SPIRE agent process.  When the agent needs to
// attest itself to the SPIRE server it:
//  1. Loads the X.509 certificate chain — either from PEM files
//     (certificate_path / intermediates_path) or from the PKCS#11 token
//     (CKO_CERTIFICATE objects identified by cert_id / cert_label)
//  2. Sends the certificate chain to the server
//  3. Receives a nonce challenge from the server
//  4. Signs the nonce using the private key stored on a PKCS#11 token (HSM)
//  5. Returns the signature to the server
//
// HCL configuration example — file-based certificate (existing behaviour):
//
//	NodeAttestor "x509pop_pkcs11" {
//	  plugin_cmd  = "/usr/local/bin/spire-plugin-pkcs11-agent"
//	  plugin_data {
//	    module_path      = "/usr/lib/softhsm/libsofthsm2.so"
//	    token_label      = "spire-node"
//	    pin              = "1234"
//	    key_id           = "01"
//	    key_label        = "node-key"
//	    certificate_path = "/opt/spire/conf/agent/agent.crt.pem"
//	  }
//	}
//
// HCL configuration example — PKCS#11 certificate (certificate stored on token):
//
//	NodeAttestor "x509pop_pkcs11" {
//	  plugin_cmd  = "/usr/local/bin/spire-plugin-pkcs11-agent"
//	  plugin_data {
//	    module_path = "/usr/lib/softhsm/libsofthsm2.so"
//	    token_label = "spire-node"
//	    pin         = "1234"
//	    key_id      = "01"
//	    key_label   = "node-key"
//	    # certificate_path omitted — leaf cert loaded from PKCS#11 token
//	    # using the same key_id / key_label as the private key.
//	  }
//	}
package agent

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	pkcs11client "github.com/aizu-hiroki/spire-plugin-node-attestor-x509pop-pkcs11/internal/pkcs11"
	nodeattestoragentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// pluginConfig holds the parsed HCL configuration.
type pluginConfig struct {
	// PKCS#11 settings.
	ModulePath string `hcl:"module_path"`
	TokenLabel string `hcl:"token_label"`
	PIN        string `hcl:"pin"`
	PINEnv     string `hcl:"pin_env"`
	KeyID      string `hcl:"key_id"`   // hex-encoded CKA_ID
	KeyLabel   string `hcl:"key_label"`

	// File-based certificate paths (optional; existing behaviour).
	CertificatePath   string `hcl:"certificate_path"`
	IntermediatesPath string `hcl:"intermediates_path"`

	// PKCS#11 certificate identifiers (optional).
	// When certificate_path is empty, the leaf cert is loaded from the token.
	// If cert_id and cert_label are also empty, key_id / key_label are used
	// as the fallback (standard PKCS#11 convention: cert shares CKA_ID with key).
	CertID    string `hcl:"cert_id"`
	CertLabel string `hcl:"cert_label"`

	// PKCS#11 intermediate certificate identifiers (optional).
	// Used when intermediates_path is empty and the intermediate cert is on the token.
	IntermediatesID    string `hcl:"intermediates_id"`
	IntermediatesLabel string `hcl:"intermediates_label"`
}

// Plugin is the agent-side x509pop_pkcs11 node attestation plugin.
type Plugin struct {
	nodeattestoragentv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu     sync.RWMutex
	cfg    *pluginConfig
	client *pkcs11client.Client
	certs  [][]byte // DER-encoded certificate chain
}

// New creates a new agent-side plugin instance.
func New() *Plugin {
	return &Plugin{}
}

// Configure parses the plugin HCL, opens the PKCS#11 session, and loads the
// certificate chain.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg := &pluginConfig{}
	if req.HclConfiguration != "" {
		if err := hcl.Decode(cfg, req.HclConfiguration); err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"failed to parse plugin configuration: %v", err)
		}
	}

	if cfg.ModulePath == "" {
		return nil, status.Error(codes.InvalidArgument, "module_path is required")
	}
	if cfg.TokenLabel == "" {
		return nil, status.Error(codes.InvalidArgument, "token_label is required")
	}
	if cfg.KeyID == "" && cfg.KeyLabel == "" {
		return nil, status.Error(codes.InvalidArgument,
			"at least one of key_id or key_label is required")
	}

	// Validate that certificate files exist before opening the PKCS#11 session.
	if cfg.CertificatePath != "" {
		if _, err := os.Stat(cfg.CertificatePath); err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"certificate_path %q: %v", cfg.CertificatePath, err)
		}
	}
	if cfg.IntermediatesPath != "" {
		if _, err := os.Stat(cfg.IntermediatesPath); err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"intermediates_path %q: %v", cfg.IntermediatesPath, err)
		}
	}

	// Resolve PIN.
	pin := cfg.PIN
	if cfg.PINEnv != "" {
		pin = os.Getenv(cfg.PINEnv)
	}

	// Decode hex key ID.
	var keyID []byte
	if cfg.KeyID != "" {
		var err error
		keyID, err = hex.DecodeString(cfg.KeyID)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"key_id is not valid hex: %v", err)
		}
	}

	// Decode optional hex cert ID.
	var certID []byte
	if cfg.CertID != "" {
		var err error
		certID, err = hex.DecodeString(cfg.CertID)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"cert_id is not valid hex: %v", err)
		}
	}

	// Decode optional hex intermediates ID.
	var intermediatesID []byte
	if cfg.IntermediatesID != "" {
		var err error
		intermediatesID, err = hex.DecodeString(cfg.IntermediatesID)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"intermediates_id is not valid hex: %v", err)
		}
	}

	// Open PKCS#11 session.
	client, err := pkcs11client.NewClient(&pkcs11client.Config{
		ModulePath: cfg.ModulePath,
		TokenLabel: cfg.TokenLabel,
		PIN:        pin,
		KeyID:      keyID,
		KeyLabel:   cfg.KeyLabel,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"failed to open PKCS#11 session: %v", err)
	}

	// Load certificates (file or PKCS#11 depending on config).
	certs, err := loadCerts(cfg, certID, intermediatesID, client)
	if err != nil {
		client.Close()
		return nil, status.Errorf(codes.InvalidArgument,
			"failed to load certificates: %v", err)
	}

	p.mu.Lock()
	if p.client != nil {
		p.client.Close()
	}
	p.cfg = cfg
	p.client = client
	p.certs = certs
	p.mu.Unlock()

	return &configv1.ConfigureResponse{}, nil
}

// attestationPayload is the JSON structure sent to the server.
type attestationPayload struct {
	Certificates [][]byte `json:"certificates"`
}

// challengeResponse is the JSON structure returned to the server after signing.
type challengeResponse struct {
	Signature []byte `json:"signature"`
}

// Close releases the underlying PKCS#11 session. It should be called when the
// plugin is no longer needed (e.g. in tests or on process shutdown).
func (p *Plugin) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil {
		p.client.Close()
		p.client = nil
	}
}

// AidAttestation is called by the SPIRE agent to perform node attestation.
func (p *Plugin) AidAttestation(stream nodeattestoragentv1.NodeAttestor_AidAttestationServer) error {
	p.mu.RLock()
	client := p.client
	certs := p.certs
	p.mu.RUnlock()

	if client == nil {
		return status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	// Step 1: Send the certificate chain as the attestation payload.
	payload, err := json.Marshal(&attestationPayload{Certificates: certs})
	if err != nil {
		return status.Errorf(codes.Internal,
			"failed to marshal attestation payload: %v", err)
	}

	if err := stream.Send(&nodeattestoragentv1.PayloadOrChallengeResponse{
		Data: &nodeattestoragentv1.PayloadOrChallengeResponse_Payload{
			Payload: payload,
		},
	}); err != nil {
		return fmt.Errorf("failed to send attestation payload: %w", err)
	}

	// Step 2: Receive the challenge (nonce) from the server.
	challenge, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil // server sent result without a challenge (already attested)
		}
		return fmt.Errorf("failed to receive challenge: %w", err)
	}

	nonce := challenge.GetChallenge()
	if len(nonce) == 0 {
		return status.Error(codes.Internal, "received empty challenge from server")
	}

	// Step 3: Sign the nonce with the PKCS#11-backed key.
	// Use the hash function appropriate for the key type (P-256→SHA-256,
	// P-384→SHA-384, P-521→SHA-512, RSA→SHA-256).
	hashFunc := client.HashFunc()
	h := hashFunc.New()
	h.Write(nonce)
	digest := h.Sum(nil)
	sig, err := client.Signer().Sign(nil, digest, hashFunc)
	if err != nil {
		return status.Errorf(codes.Internal,
			"failed to sign challenge with PKCS#11 key: %v", err)
	}

	// Step 4: Send the signature back to the server.
	resp, err := json.Marshal(&challengeResponse{Signature: sig})
	if err != nil {
		return status.Errorf(codes.Internal,
			"failed to marshal challenge response: %v", err)
	}

	if err := stream.Send(&nodeattestoragentv1.PayloadOrChallengeResponse{
		Data: &nodeattestoragentv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: resp,
		},
	}); err != nil {
		return fmt.Errorf("failed to send challenge response: %w", err)
	}

	return nil
}

// loadCerts builds the DER certificate chain from either PEM files or the
// PKCS#11 token, depending on which config fields are populated.
func loadCerts(cfg *pluginConfig, certID, intermediatesID []byte, client *pkcs11client.Client) ([][]byte, error) {
	var leafDER []byte

	if cfg.CertificatePath != "" {
		// File mode: existing behaviour.
		fileCerts, err := loadPEMCerts(cfg.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("certificate_path: %w", err)
		}
		if len(fileCerts) == 0 {
			return nil, fmt.Errorf("no certificates found in %s", cfg.CertificatePath)
		}
		leafDER = fileCerts[0]
	} else {
		// PKCS#11 mode: load leaf cert from the token.
		der, err := client.LoadCertificate(certID, cfg.CertLabel)
		if err != nil {
			return nil, fmt.Errorf("load leaf certificate from PKCS#11: %w", err)
		}
		leafDER = der
	}

	// Validate the leaf certificate.
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("leaf certificate does not have digitalSignature key usage")
	}

	certs := [][]byte{leafDER}

	// Load intermediate certificates.
	if cfg.IntermediatesPath != "" {
		intermediates, err := loadPEMCerts(cfg.IntermediatesPath)
		if err != nil {
			return nil, fmt.Errorf("intermediates_path: %w", err)
		}
		certs = append(certs, intermediates...)
	} else if len(intermediatesID) > 0 || cfg.IntermediatesLabel != "" {
		der, err := client.LoadCertificate(intermediatesID, cfg.IntermediatesLabel)
		if err != nil {
			return nil, fmt.Errorf("load intermediate certificate from PKCS#11: %w", err)
		}
		certs = append(certs, der)
	}

	return certs, nil
}

func loadPEMCerts(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
	return certs, nil
}
