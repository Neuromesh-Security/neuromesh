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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func mustPKCS8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestParsePKCS8SignerEd25519RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParsePKCS8Signer(mustPKCS8PEM(t, priv))
	if err != nil {
		t.Fatalf("ParsePKCS8Signer: %v", err)
	}
	msg := []byte(`{"schema_version":2,"deny_path_prefixes":["/tmp/"]}`)
	sigB64, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("b64: %v", err)
	}
	if !ed25519.Verify(pub, msg, raw) {
		t.Fatal("ed25519 verify failed")
	}
}

func TestParsePKCS8SignerECDSAP256RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParsePKCS8Signer(mustPKCS8PEM(t, priv))
	if err != nil {
		t.Fatalf("ParsePKCS8Signer: %v", err)
	}
	msg := []byte("policy-bundle-body")
	sigB64, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("b64: %v", err)
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(&priv.PublicKey, sum[:], raw) {
		t.Fatal("ecdsa verify failed")
	}
}

func TestLoadSignerFromEnv(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(path, mustPKCS8PEM(t, priv), 0o600); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvPolicyBundleSigningKeyPath, abs)
	s, err := LoadSignerFromEnv()
	if err != nil {
		t.Fatalf("LoadSignerFromEnv: %v", err)
	}
	if _, err := s.Sign([]byte("x")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestLoadSignerFromEnvMissing(t *testing.T) {
	t.Setenv(EnvPolicyBundleSigningKeyPath, "")
	if _, err := LoadSignerFromEnv(); err == nil {
		t.Fatal("expected error when signing key unset")
	}
}

func TestLoadSignerFromEnvRejectsRelative(t *testing.T) {
	t.Setenv(EnvPolicyBundleSigningKeyPath, "relative/key.pem")
	if _, err := LoadSignerFromEnv(); err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestHandlerSignsExactBodyBytes(t *testing.T) {
	const token = "tok"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParsePKCS8Signer(mustPKCS8PEM(t, priv))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	Handler([]string{token}, s).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%q", rr.Code, rr.Body.String())
	}
	body := rr.Body.Bytes()
	sigB64 := rr.Header().Get(HeaderPolicyBundleSignature)
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, body, raw) {
		t.Fatal("signature must cover exact response body bytes")
	}
}
