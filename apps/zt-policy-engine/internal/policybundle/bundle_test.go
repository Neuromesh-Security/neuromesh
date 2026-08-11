package policybundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)


func testEd25519Signer(t *testing.T) Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	s, err := ParsePKCS8Signer(pemBytes)
	if err != nil {
		t.Fatalf("ParsePKCS8Signer: %v", err)
	}
	return s
}

func TestCurrentReturnsSchemaVersion2WithIdentity(t *testing.T) {
	now := time.Date(2026, 7, 25, 19, 0, 0, 0, time.UTC)
	b := CurrentAt(now)
	if b.SchemaVersion != 2 {
		t.Fatalf("schema_version: got %d want 2", b.SchemaVersion)
	}
	want := []string{"/tmp/", "/dev/shm/", "/var/tmp/"}
	if len(b.DenyPathPrefixes) != len(want) {
		t.Fatalf("prefix count: got %d want %d", len(b.DenyPathPrefixes), len(want))
	}
	for i := range want {
		if b.DenyPathPrefixes[i] != want[i] {
			t.Fatalf("prefix[%d]: got %q want %q", i, b.DenyPathPrefixes[i], want[i])
		}
	}
	if b.IdentityAllowExceptions == nil {
		t.Fatal("identity_allow_exceptions must be present")
	}
	ie := b.IdentityAllowExceptions
	if ie.ScopePathPrefix != IdentityExceptionScopePrefix {
		t.Fatalf("scope: got %q want %q", ie.ScopePathPrefix, IdentityExceptionScopePrefix)
	}
	if len(ie.SpiffeIDs) != 3 {
		t.Fatalf("spiffe_ids count: got %d want 3", len(ie.SpiffeIDs))
	}
	for _, id := range ie.SpiffeIDs {
		if !strings.Contains(id, "/ns/default/sa/") {
			t.Fatalf("expected path-form SPIFFE ID, got %q", id)
		}
	}
	if ie.IssuedAt != "2026-07-25T19:00:00Z" {
		t.Fatalf("issued_at: got %q", ie.IssuedAt)
	}
	if ie.ExpiresAt != "2026-07-25T19:01:30Z" {
		t.Fatalf("expires_at: got %q want +90s", ie.ExpiresAt)
	}
	if b.Version == "" || b.Version[:7] != "sha256:" {
		t.Fatalf("version must be sha256-prefixed, got %q", b.Version)
	}
}

func TestVersionStableForIdenticalContentIgnoresClock(t *testing.T) {
	a := CurrentAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	b := CurrentAt(time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC))
	if a.Version != b.Version {
		t.Fatalf("version must ignore issued_at clock skew: %q vs %q", a.Version, b.Version)
	}
	if a.IdentityAllowExceptions.ExpiresAt == b.IdentityAllowExceptions.ExpiresAt {
		t.Fatal("expires_at must advance with clock")
	}
}

func TestVersionChangesWhenIdentityIDsChange(t *testing.T) {
	base := contentVersion(BootstrapDenyPathPrefixes, BootstrapIdentityAllowSPIFFEIDS, IdentityExceptionScopePrefix)
	altered := contentVersion(BootstrapDenyPathPrefixes, []string{"spiffe://x/ns/default/sa/other"}, IdentityExceptionScopePrefix)
	if base == altered {
		t.Fatal("version must change when identity allowlist changes")
	}
}

func TestVersionChangesWhenPrefixesChange(t *testing.T) {
	base := contentVersion(BootstrapDenyPathPrefixes, BootstrapIdentityAllowSPIFFEIDS, IdentityExceptionScopePrefix)
	altered := contentVersion([]string{"/tmp/", "/dev/shm/", "/var/tmp/", "/evil/"}, BootstrapIdentityAllowSPIFFEIDS, IdentityExceptionScopePrefix)
	if base == altered {
		t.Fatal("version must change when underlying prefix set changes")
	}
}

func TestHandlerValidBearerReturnsBundle(t *testing.T) {
	const token = "test-policy-bundle-token"
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	Handler(token, testEd25519Signer(t)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%q", rr.Code, http.StatusOK, rr.Body.String())
	}

	var got Bundle
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SchemaVersion != 2 {
		t.Fatalf("schema_version: got %d want 2", got.SchemaVersion)
	}
	if got.IdentityAllowExceptions == nil || len(got.IdentityAllowExceptions.SpiffeIDs) != 3 {
		t.Fatal("expected identity_allow_exceptions with 3 spiffe_ids")
	}
	if len(got.DenyPathPrefixes) != 3 {
		t.Fatalf("expected 3 prefixes, got %d", len(got.DenyPathPrefixes))
	}
	if rr.Header().Get(HeaderPolicyBundleSignature) == "" {
		t.Fatal("expected X-Neuromesh-Policy-Bundle-Signature header")
	}
}

func TestHandlerNilSignerUnavailable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	Handler("tok", nil).ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestHandlerMissingCredentialRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	rr := httptest.NewRecorder()
	Handler("expected-token", testEd25519Signer(t)).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerInvalidCredentialRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	Handler("expected-token", testEd25519Signer(t)).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerEmptyConfiguredTokenUnavailable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rr := httptest.NewRecorder()
	Handler("", testEd25519Signer(t)).ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestHandlerRejectsNonGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	Handler("tok", testEd25519Signer(t)).ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestLoadTokenFromEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvPolicyBundleTokenFile, abs)
	t.Setenv(EnvPolicyBundleToken, "")
	got, err := LoadTokenFromEnv()
	if err != nil {
		t.Fatalf("LoadTokenFromEnv: %v", err)
	}
	if got != "file-token" {
		t.Fatalf("got %q want file-token", got)
	}
}

func TestLoadTokenFromEnvFileRejectsRelativePath(t *testing.T) {
	t.Setenv(EnvPolicyBundleTokenFile, "relative/token")
	t.Setenv(EnvPolicyBundleToken, "")
	if _, err := LoadTokenFromEnv(); err == nil {
		t.Fatal("expected error for relative token file path")
	}
}

func TestLoadTokenFromEnvMissing(t *testing.T) {
	t.Setenv(EnvPolicyBundleTokenFile, "")
	t.Setenv(EnvPolicyBundleToken, "")
	if _, err := LoadTokenFromEnv(); err == nil {
		t.Fatal("expected error when token unset")
	}
}
