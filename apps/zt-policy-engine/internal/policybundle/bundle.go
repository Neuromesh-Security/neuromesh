//! Compiled path-prefix deny-list export for agent-side BPF map sync (Phase 1).
//!
//! This package is intentionally separate from `/v1/evaluate`: it does not run
//! OPA or SPIFFE validation. It exports the same bootstrap deny prefixes the
//! LSM historically hard-coded so the agent can keep deciding in-kernel via a
//! BPF array map lookup.
//!
//! GET /v1/policy-bundle requires a shared bearer token (Issue #55). See auth.go.
package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
)

// SchemaVersion is the JSON schema revision of the policy bundle document.
const SchemaVersion = 1

// BootstrapDenyPathPrefixes is the Phase-1 deny set. It matches the LSM's
// historical hardcoded prefixes (/tmp/, /dev/shm/, /var/tmp/) — NOT the narrower
// Rego special-case of only /tmp/. Widening or narrowing this set is a
// deliberate policy change and must not happen silently.
//
// Phase 2 identity exceptions (future) apply ONLY to /tmp/ per Rego; /dev/shm/
// and /var/tmp/ remain hard-denied regardless of SPIFFE identity (see
// docs/threat-model.md).
var BootstrapDenyPathPrefixes = []string{
	"/tmp/",
	"/dev/shm/",
	"/var/tmp/",
}

// Bundle is the versioned deny-list document returned by GET /v1/policy-bundle.
type Bundle struct {
	SchemaVersion    int      `json:"schema_version"`
	Version          string   `json:"version"`
	DenyPathPrefixes []string `json:"deny_path_prefixes"`
}

// Current returns the active Phase-1 bundle and a content-addressed version
// that changes only when the prefix set changes.
func Current() Bundle {
	prefixes := append([]string(nil), BootstrapDenyPathPrefixes...)
	return Bundle{
		SchemaVersion:    SchemaVersion,
		Version:          contentVersion(prefixes),
		DenyPathPrefixes: prefixes,
	}
}

func contentVersion(prefixes []string) string {
	joined := strings.Join(prefixes, "\n")
	sum := sha256.Sum256([]byte(joined))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Handler serves GET /v1/policy-bundle and requires a valid Bearer token.
// expectedToken must be non-empty (loaded at process startup via LoadTokenFromEnv).
func Handler(expectedToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if expectedToken == "" {
			http.Error(w, "policy-bundle authentication not configured", http.StatusServiceUnavailable)
			return
		}
		if !authorizeBearer(r, expectedToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="neuromesh-policy-bundle"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(Current()); err != nil {
			http.Error(w, "failed to encode policy bundle", http.StatusInternalServerError)
		}
	}
}
