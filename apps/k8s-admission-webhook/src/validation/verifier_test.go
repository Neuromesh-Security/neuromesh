package validation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// generateTestECDSAPublicKeyPEM creates a real ECDSA P-256 keypair in memory
// and PEM-encodes the public half, exactly the format operators are expected
// to mount from a Kubernetes Secret in production. No mocking of the crypto
// primitives happens anywhere in this test.
func generateTestECDSAPublicKeyPEM(t *testing.T) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestNewCosignKeyVerifier_LoadsRealPublicKeyMaterial(t *testing.T) {
	t.Parallel()

	pubPEM := generateTestECDSAPublicKeyPEM(t)

	verifier, err := NewCosignKeyVerifier(pubPEM, false, time.Second, false)
	if err != nil {
		t.Fatalf("NewCosignKeyVerifier: %v", err)
	}
	if verifier.verifier == nil {
		t.Fatal("expected an underlying sigstore signature.Verifier to be constructed")
	}
	if verifier.keyFingerprint == "" {
		t.Fatal("expected a non-empty key fingerprint to be computed for audit logging")
	}
	if verifier.insecure {
		t.Fatal("expected insecure registry flag to default to false")
	}

	// The verifier's own PublicKey() must round-trip to a usable crypto key
	// (proves LoadPublicKeyRaw actually parsed real key material, not a stub).
	pub, err := verifier.verifier.PublicKey()
	if err != nil {
		t.Fatalf("underlying verifier.PublicKey(): %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestNewCosignKeyVerifier_RejectsInvalidPEM(t *testing.T) {
	t.Parallel()

	_, err := NewCosignKeyVerifier([]byte("not a pem encoded key"), false, time.Second, false)
	if err == nil {
		t.Fatal("expected an error for invalid/garbage public key material")
	}
}

func TestNewCosignKeyVerifier_InsecureRegistryFlag(t *testing.T) {
	t.Parallel()

	pubPEM := generateTestECDSAPublicKeyPEM(t)
	verifier, err := NewCosignKeyVerifier(pubPEM, false, time.Second, true)
	if err != nil {
		t.Fatalf("NewCosignKeyVerifier: %v", err)
	}
	if !verifier.insecure {
		t.Fatal("expected insecure registry flag to be true when requested")
	}
}

func TestNewCosignKeyVerifier_FingerprintIsDeterministicPerKey(t *testing.T) {
	t.Parallel()

	pubPEM := generateTestECDSAPublicKeyPEM(t)

	v1, err := NewCosignKeyVerifier(pubPEM, false, time.Second, false)
	if err != nil {
		t.Fatalf("NewCosignKeyVerifier: %v", err)
	}
	v2, err := NewCosignKeyVerifier(pubPEM, false, time.Second, false)
	if err != nil {
		t.Fatalf("NewCosignKeyVerifier: %v", err)
	}

	if v1.keyFingerprint != v2.keyFingerprint {
		t.Fatalf("expected stable fingerprint for identical key material: %q vs %q", v1.keyFingerprint, v2.keyFingerprint)
	}

	otherPubPEM := generateTestECDSAPublicKeyPEM(t)
	v3, err := NewCosignKeyVerifier(otherPubPEM, false, time.Second, false)
	if err != nil {
		t.Fatalf("NewCosignKeyVerifier: %v", err)
	}
	if v1.keyFingerprint == v3.keyFingerprint {
		t.Fatal("expected different keys to produce different fingerprints")
	}
}

func TestResolveImageDigest_AlreadyDigestPinnedSkipsRegistryLookup(t *testing.T) {
	t.Parallel()

	wantDigest := "sha256:" + strings.Repeat("0", 64)
	pinned := "example.invalid/repo@" + wantDigest

	// example.invalid is unresolvable; if resolveImageDigest tried to reach
	// the registry for an already-digest-pinned reference, this would hang
	// or fail on DNS. It must return immediately using the embedded digest.
	digestRef, err := resolveImageDigest(context.Background(), pinned, false)
	if err != nil {
		t.Fatalf("expected already-pinned digest reference to resolve without network access, got error: %v", err)
	}
	if digestRef.DigestStr() != wantDigest {
		t.Fatalf("expected digest %q to be echoed back unchanged, got %q", wantDigest, digestRef.DigestStr())
	}
}

func TestResolveImageDigest_RejectsMalformedReference(t *testing.T) {
	t.Parallel()

	_, err := resolveImageDigest(context.Background(), "not a valid image reference!!", false)
	if err == nil {
		t.Fatal("expected an error for a malformed image reference")
	}
}

func TestResolveImageDigest_InsecureAllowsHTTPSchemeHost(t *testing.T) {
	t.Parallel()

	wantDigest := "sha256:" + strings.Repeat("a", 64)
	pinned := "kind-registry:5000/repo@" + wantDigest

	// With insecure=true, a non-localhost HTTP registry hostname parses as an
	// insecure digest ref (scheme http). Without it, ParseReference still
	// succeeds for digest-pinned refs, but registry transport would use HTTPS.
	digestRef, err := resolveImageDigest(context.Background(), pinned, true)
	if err != nil {
		t.Fatalf("resolveImageDigest insecure: %v", err)
	}
	if digestRef.DigestStr() != wantDigest {
		t.Fatalf("expected digest %q, got %q", wantDigest, digestRef.DigestStr())
	}
	if digestRef.Context().Registry.Scheme() != "http" {
		t.Fatalf("expected http scheme for insecure registry ref, got %q", digestRef.Context().Registry.Scheme())
	}
}

func TestNewCosignKeylessVerifier_FailsClosedWhenNotConfigured(t *testing.T) {
	t.Parallel()

	if _, err := NewCosignKeylessVerifier("", "", time.Second); err == nil {
		t.Fatal("expected an error when issuer/subject are not configured")
	}
}

func TestCosignKeylessVerifier_VerifyImageAlwaysFailsClosed(t *testing.T) {
	t.Parallel()

	verifier, err := NewCosignKeylessVerifier("https://issuer.example.com", "signer@example.com", time.Second)
	if err != nil {
		t.Fatalf("NewCosignKeylessVerifier: %v", err)
	}

	result, err := verifier.VerifyImage(context.Background(), "registry.example.com/app:v1")
	if err == nil {
		t.Fatal("expected keyless verification (not yet implemented) to fail closed with an error")
	}
	if result != nil {
		t.Fatalf("expected a nil result on failure, got: %+v", result)
	}
}

func TestNewVerifierFromEnv_RejectsUnknownMode(t *testing.T) {
	// Not t.Parallel(): t.Setenv is incompatible with parallel subtests.
	t.Setenv(EnvCosignVerifyMode, "totally-bogus-mode")

	if _, err := NewVerifierFromEnv(); err == nil {
		t.Fatal("expected an error for an unsupported verify mode")
	}
}

func TestNewVerifierFromEnv_KeyModeFailsClosedWhenKeyFileMissing(t *testing.T) {
	// Not t.Parallel(): t.Setenv is incompatible with parallel subtests.
	t.Setenv(EnvCosignVerifyMode, VerifyModeKey)
	t.Setenv(EnvCosignPublicKeyPath, "/nonexistent/path/cosign.pub")

	if _, err := NewVerifierFromEnv(); err == nil {
		t.Fatal("expected startup to fail closed when the configured public key file cannot be read")
	}
}
