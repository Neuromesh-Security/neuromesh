//! Compiled path-prefix deny-list + identity-allow export for agent BPF sync.
//!
//! This package is intentionally separate from `/v1/evaluate`: it does not run
//! OPA or SPIFFE validation. It exports the Phase-1 deny prefixes and the
//! Slice 2a identity-allow exception document (schema_version 2).
//!
//! GET /v1/policy-bundle requires a shared bearer token (Issue #55). See auth.go.
package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// SchemaVersion is the JSON schema revision of the policy bundle document.
// Slice 2a: identity_allow_exceptions requires schema_version 2.
const SchemaVersion = 2

// IdentityExceptionTTL is how long a freshly issued identity section remains
// valid. Matches 3× the agent POLICY_SYNC_INTERVAL (30s). After expires_at,
// the agent MUST set IDENTITY_EXCEPTIONS_VALID=0 — invalidating ALL exceptions
// (including manually seeded cgroup IDs). No grace-period workaround.
const IdentityExceptionTTL = 90 * time.Second

// IdentityExceptionScopePrefix is the only path prefix for which identity
// exceptions may apply. Agent rejects any other scope_path_prefix value.
const IdentityExceptionScopePrefix = "/tmp/"

// BootstrapDenyPathPrefixes is the Phase-1 deny set. It matches the LSM's
// historical hardcoded prefixes (/tmp/, /dev/shm/, /var/tmp/) — NOT the narrower
// Rego special-case of only /tmp/. Widening or narrowing this set is a
// deliberate policy change and must not happen silently.
//
// Phase 2 identity exceptions apply ONLY to /tmp/ per Rego; /dev/shm/
// and /var/tmp/ remain hard-denied regardless of SPIFFE identity (see
// docs/threat-model.md).
var BootstrapDenyPathPrefixes = []string{
	"/tmp/",
	"/dev/shm/",
	"/var/tmp/",
}

// BootstrapIdentityAllowSPIFFEIDS are the path-form SPIFFE IDs Rego trusts
// for /tmp/ ephemeral execution. Canonical form matches real SPIRE K8s SVIDs
// (spiffe://{trust}/ns/{ns}/sa/{sa}) — not the former flat shorthand.
var BootstrapIdentityAllowSPIFFEIDS = []string{
	"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
	"spiffe://neuromesh.security/ns/default/sa/zt-policy-engine",
	"spiffe://neuromesh.security/ns/default/sa/ai-threat-detector",
}

// IdentityAllowExceptions is the Slice 2a identity section of the policy bundle.
type IdentityAllowExceptions struct {
	ScopePathPrefix string   `json:"scope_path_prefix"`
	SpiffeIDs       []string `json:"spiffe_ids"`
	IssuedAt        string   `json:"issued_at"`
	ExpiresAt       string   `json:"expires_at"`
}

// Bundle is the versioned deny-list (+ identity exceptions) document returned
// by GET /v1/policy-bundle.
type Bundle struct {
	SchemaVersion            int                       `json:"schema_version"`
	Version                  string                    `json:"version"`
	DenyPathPrefixes         []string                  `json:"deny_path_prefixes"`
	IdentityAllowExceptions  *IdentityAllowExceptions  `json:"identity_allow_exceptions"`
}

// Current returns the active schema_version 2 bundle. issued_at/expires_at are
// wall-clock; content version hashes deny prefixes + identity IDs + scope only
// (timestamps intentionally excluded so TTL refresh does not churn version).
func Current() Bundle {
	return CurrentAt(time.Now().UTC())
}

// CurrentAt is Current with an injectable clock (tests).
func CurrentAt(now time.Time) Bundle {
	prefixes := append([]string(nil), BootstrapDenyPathPrefixes...)
	ids := append([]string(nil), BootstrapIdentityAllowSPIFFEIDS...)
	issued := now.UTC()
	expires := issued.Add(IdentityExceptionTTL)
	return Bundle{
		SchemaVersion:    SchemaVersion,
		Version:          contentVersion(prefixes, ids, IdentityExceptionScopePrefix),
		DenyPathPrefixes: prefixes,
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: IdentityExceptionScopePrefix,
			SpiffeIDs:       ids,
			IssuedAt:        issued.Format(time.RFC3339),
			ExpiresAt:       expires.Format(time.RFC3339),
		},
	}
}

func contentVersion(prefixes, spiffeIDs []string, scope string) string {
	var b strings.Builder
	b.WriteString("deny:\n")
	b.WriteString(strings.Join(prefixes, "\n"))
	b.WriteString("\nscope:\n")
	b.WriteString(scope)
	b.WriteString("\nspiffe:\n")
	b.WriteString(strings.Join(spiffeIDs, "\n"))
	sum := sha256.Sum256([]byte(b.String()))
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
