package policybundle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentReturnsBootstrapPrefixes(t *testing.T) {
	b := Current()
	if b.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version: got %d want %d", b.SchemaVersion, SchemaVersion)
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
	if b.Version == "" || b.Version[:7] != "sha256:" {
		t.Fatalf("version must be sha256-prefixed, got %q", b.Version)
	}
}

func TestVersionStableForIdenticalContent(t *testing.T) {
	a := Current()
	b := Current()
	if a.Version != b.Version {
		t.Fatalf("version not stable: %q vs %q", a.Version, b.Version)
	}
}

func TestVersionChangesWhenPrefixesChange(t *testing.T) {
	base := contentVersion(BootstrapDenyPathPrefixes)
	altered := contentVersion([]string{"/tmp/", "/dev/shm/", "/var/tmp/", "/evil/"})
	if base == altered {
		t.Fatal("version must change when underlying prefix set changes")
	}
}

func TestHandlerValidBearerReturnsBundle(t *testing.T) {
	const token = "test-policy-bundle-token"
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	Handler(token).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%q", rr.Code, http.StatusOK, rr.Body.String())
	}

	var got Bundle
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := Current()
	if got.Version != want.Version {
		t.Fatalf("version: got %q want %q", got.Version, want.Version)
	}
	if len(got.DenyPathPrefixes) != 3 {
		t.Fatalf("expected 3 prefixes, got %d", len(got.DenyPathPrefixes))
	}
}

func TestHandlerMissingCredentialRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	rr := httptest.NewRecorder()
	Handler("expected-token").ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerInvalidCredentialRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	Handler("expected-token").ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerEmptyConfiguredTokenUnavailable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rr := httptest.NewRecorder()
	Handler("").ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestHandlerRejectsNonGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	Handler("tok").ServeHTTP(rr, req)
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
	t.Setenv(EnvPolicyBundleTokenFile, path)
	t.Setenv(EnvPolicyBundleToken, "")
	got, err := LoadTokenFromEnv()
	if err != nil {
		t.Fatalf("LoadTokenFromEnv: %v", err)
	}
	if got != "file-token" {
		t.Fatalf("got %q want file-token", got)
	}
}

func TestLoadTokenFromEnvMissing(t *testing.T) {
	t.Setenv(EnvPolicyBundleTokenFile, "")
	t.Setenv(EnvPolicyBundleToken, "")
	if _, err := LoadTokenFromEnv(); err == nil {
		t.Fatal("expected error when token unset")
	}
}
