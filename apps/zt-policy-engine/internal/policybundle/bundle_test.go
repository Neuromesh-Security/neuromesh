package policybundle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestHandlerReturnsExpectedJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusOK)
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
	for i, p := range []string{"/tmp/", "/dev/shm/", "/var/tmp/"} {
		if got.DenyPathPrefixes[i] != p {
			t.Fatalf("prefix[%d]: got %q want %q", i, got.DenyPathPrefixes[i], p)
		}
	}
}

func TestHandlerRejectsNonGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/policy-bundle", nil)
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}
