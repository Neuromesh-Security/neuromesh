//! Cosign sign-blob-compatible detached signatures over the policy-bundle body.
//!
//! # Trust model
//!
//! Bearer token = transport auth (who may fetch). Signature = content integrity
//! (what was authorized to be applied). Both are required; neither replaces the
//! other (external Rego/policy-bundle security review P0).
//!
//! Wire format matches agent `verify_cosign_blob_signature`:
//!   - message = exact HTTP response body bytes (no re-serialization on verify)
//!   - signature = standard base64 of ECDSA P-256 DER (or fixed-size) / Ed25519
//!     raw 64-byte signature
//!   - header = X-Neuromesh-Policy-Bundle-Signature
//!
//! Private key: PKCS#8 PEM (unencrypted), ECDSA P-256 or Ed25519 - the same
//! SubjectPublicKeyInfo types Cosign static keys expose as .pub.
package policybundle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// HeaderPolicyBundleSignature carries the Cosign-compatible detached signature
	// over the exact response body bytes.
	HeaderPolicyBundleSignature = "X-Neuromesh-Policy-Bundle-Signature"

	// EnvPolicyBundleSigningKeyPath is the absolute path to the PKCS#8 PEM
	// private key used to sign GET /v1/policy-bundle bodies.
	EnvPolicyBundleSigningKeyPath = "NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH"
)

// Signer produces Cosign sign-blob-compatible detached signatures.
type Signer interface {
	Sign(message []byte) (signatureBase64 string, err error)
}

type ecdsaP256Signer struct {
	key *ecdsa.PrivateKey
}

func (s *ecdsaP256Signer) Sign(message []byte) (string, error) {
	sum := sha256.Sum256(message)
	der, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

type ed25519Signer struct {
	key ed25519.PrivateKey
}

func (s *ed25519Signer) Sign(message []byte) (string, error) {
	sig := ed25519.Sign(s.key, message)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// LoadSignerFromEnv loads the policy-bundle signing key. Fail-closed: missing /
// empty / unreadable / unsupported key is an error (server must not serve
// unsigned bundles).
func LoadSignerFromEnv() (Signer, error) {
	path := strings.TrimSpace(os.Getenv(EnvPolicyBundleSigningKeyPath))
	if path == "" {
		return nil, fmt.Errorf(
			"policy-bundle signing required: set %s to an absolute PKCS#8 PEM path",
			EnvPolicyBundleSigningKeyPath,
		)
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s must be an absolute path, got %q", EnvPolicyBundleSigningKeyPath, path)
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s (%q): %w", EnvPolicyBundleSigningKeyPath, path, err)
	}
	return ParsePKCS8Signer(pemBytes)
}

// ParsePKCS8Signer parses an unencrypted PKCS#8 PEM private key (ECDSA P-256 or Ed25519).
func ParsePKCS8Signer(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("policy-bundle signing key: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("policy-bundle signing key: parse PKCS#8: %w", err)
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("policy-bundle signing key: ECDSA curve must be P-256")
		}
		return &ecdsaP256Signer{key: k}, nil
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("policy-bundle signing key: invalid Ed25519 private key length")
		}
		return &ed25519Signer{key: k}, nil
	default:
		return nil, fmt.Errorf("policy-bundle signing key: unsupported type %T (want ECDSA P-256 or Ed25519)", key)
	}
}

// SignMessage is a thin wrapper around Signer.Sign (tests / helpers).
func SignMessage(s Signer, message []byte) (string, error) {
	return s.Sign(message)
}
