//! Compiled path-prefix deny-list + identity-allow export for agent BPF sync.
//!
//! This package is intentionally separate from `/v1/evaluate`: it does not run
//! OPA or SPIFFE validation. It exports the Phase-1 deny prefixes and the
//! Slice 2a identity-allow exception document (schema_version 3: identity
//! section plus whole-bundle temporal binding — T-PB-04).
//!
//! GET /v1/policy-bundle requires a shared bearer token (Issue #55). See auth.go.
package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// SchemaVersion is the JSON schema revision of the policy bundle document.
// Schema 3: schema 2 identity_allow_exceptions plus top-level not_before /
// not_after (RFC3339) for anti-replay temporal binding (T-PB-04).
const SchemaVersion = 3

// DefaultBundleValidityWindow is 10 × the agent POLICY_SYNC_INTERVAL (30s).
// Aligns with POLICY_STALE_AFTER (5 min) as one coherent freshness horizon.
const DefaultBundleValidityWindow = 300 * time.Second

// EnvPolicyBundleValiditySecs overrides DefaultBundleValidityWindow (seconds).
// Intended for live short-window anti-replay tests only.
const EnvPolicyBundleValiditySecs = "NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS"

// IdentityExceptionTTL is how long a freshly issued identity section remains
// valid. Matches 3× the agent POLICY_SYNC_INTERVAL (30s). After expires_at,
// the agent MUST set IDENTITY_EXCEPTIONS_VALID=0 — invalidating ALL exceptions
// (including manually seeded cgroup IDs). No grace-period workaround.
// Distinct from whole-bundle not_before/not_after (T-PB-04).
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
//
// not_before / not_after sit INSIDE the Cosign-signed body (T-PB-04). Stripping
// or altering them invalidates the signature. They are independent of
// identity_allow_exceptions.expires_at (identity VALID TTL only).
type Bundle struct {
	SchemaVersion           int                      `json:"schema_version"`
	Version                 string                   `json:"version"`
	NotBefore               string                   `json:"not_before"`
	NotAfter                string                   `json:"not_after"`
	DenyPathPrefixes        []string                 `json:"deny_path_prefixes"`
	IdentityAllowExceptions *IdentityAllowExceptions `json:"identity_allow_exceptions"`
}

// ValidityWindowFromEnv returns the whole-bundle validity window.
// NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS overrides the 300s default when set to
// a positive integer (live short-window tests). Invalid/empty → default.
func ValidityWindowFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(EnvPolicyBundleValiditySecs))
	if raw == "" {
		return DefaultBundleValidityWindow
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || secs <= 0 {
		return DefaultBundleValidityWindow
	}
	return time.Duration(secs) * time.Second
}

// Current returns the active schema_version 3 bundle. issued_at/expires_at and
// not_before/not_after are wall-clock; content version hashes deny prefixes +
// identity IDs + scope only (timestamps intentionally excluded so TTL /
// temporal refresh does not churn version).
func Current() Bundle {
	return CurrentAt(time.Now().UTC())
}

// CurrentAt is Current with an injectable clock (tests).
func CurrentAt(now time.Time) Bundle {
	prefixes := append([]string(nil), BootstrapDenyPathPrefixes...)
	ids := append([]string(nil), BootstrapIdentityAllowSPIFFEIDS...)
	issued := now.UTC()
	expires := issued.Add(IdentityExceptionTTL)
	window := ValidityWindowFromEnv()
	return Bundle{
		SchemaVersion:    SchemaVersion,
		Version:          contentVersion(prefixes, ids, IdentityExceptionScopePrefix),
		NotBefore:        issued.Format(time.RFC3339),
		NotAfter:         issued.Add(window).Format(time.RFC3339),
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

// Handler serves GET /v1/policy-bundle and requires a valid Bearer token plus a
// Cosign-compatible detached signature over the exact response body bytes.
// expectedToken must be non-empty (LoadTokenFromEnv). signer must be non-nil
// (LoadSignerFromEnv); a nil signer returns 503 (fail-closed, never unsigned).
func Handler(expectedToken string, signer Signer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if expectedToken == "" {
			http.Error(w, "policy-bundle authentication not configured", http.StatusServiceUnavailable)
			return
		}
		if signer == nil {
			http.Error(w, "policy-bundle signing not configured", http.StatusServiceUnavailable)
			return
		}
		if !authorizeBearer(r, expectedToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="neuromesh-policy-bundle"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		body, err := json.Marshal(Current())
		if err != nil {
			http.Error(w, "failed to encode policy bundle", http.StatusInternalServerError)
			return
		}
		// Match historical json.Encoder trailing newline so signed bytes are stable.
		body = append(body, '\n')

		sigB64, err := signer.Sign(body)
		if err != nil {
			http.Error(w, "failed to sign policy bundle", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(HeaderPolicyBundleSignature, sigB64)
		_, _ = w.Write(body)
	}
}
