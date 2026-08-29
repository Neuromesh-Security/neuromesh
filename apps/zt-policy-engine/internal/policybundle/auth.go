//! Authentication for GET /v1/policy-bundle (Issue #55 / Phase 2 Slice 0).
//!
//! # Mechanism choice (honest)
//!
//! mTLS via SPIFFE/SPIRE would reuse `spiffe_validator.go` and match zero-trust
//! architecture, but this repository's deploy model does **not** ship SPIRE on
//! nodes (DaemonSet has no Workload API socket; docker-compose explicitly has
//! no SPIRE agent). Requiring SPIRE here would invent platform ops this
//! solo-maintained project cannot yet run reliably.
//!
//! Therefore Slice 0 uses a **static shared bearer token**, delivered like the
//! Cosign public-key Secret (env or mounted file). Same credential class as
//! Cosign static keys: long-lived, must be provisioned/rotated/protected —
//! justified by current ops maturity, not by defaulting to "easier code."
//!
//! Issue #179: PE accepts an N/N+1 **set** during dual-trust rotation (never a
//! hard swap). Fingerprints in metrics are truncated SHA-256 hex only — never
//! the raw token.
//!
//! Unauthenticated or invalid credentials are rejected. There is no
//! unauthenticated fallback path.
package policybundle

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	// EnvPolicyBundleToken is the shared bearer token (plaintext env — prefer file in prod).
	// May contain a single token only (lab). Prefer EnvPolicyBundleTokenFile for dual-accept.
	EnvPolicyBundleToken = "NEUROMESH_POLICY_BUNDLE_TOKEN"
	// EnvPolicyBundleTokenFile is an absolute path to a file containing one or more
	// accepted tokens (newline-separated). Kubernetes: Secret key `accepted`.
	EnvPolicyBundleTokenFile = "NEUROMESH_POLICY_BUNDLE_TOKEN_FILE"
	// EnvPolicyBundleTokenPreviousFile is an optional absolute path to a second
	// accepted token file (Secret key `token-previous` during dual-trust rotation).
	EnvPolicyBundleTokenPreviousFile = "NEUROMESH_POLICY_BUNDLE_TOKEN_PREVIOUS_FILE"

	// TokenFingerprintHexLen is the Prometheus label length (truncated SHA-256 hex).
	// 8 hex chars = 32 bits of digest — opaque, not reversible to the secret.
	TokenFingerprintHexLen = 8
)

// TokenFingerprint returns truncated SHA-256 hex of token bytes (Issue #179).
// Never log or export the raw token; metrics/labels use only this value.
func TokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:TokenFingerprintHexLen/2])
}

// LoadTokenFromEnv is retained for callers that need a single token (tests / lab).
// Prefer LoadTokensFromEnv for PE dual-accept (Issue #179).
func LoadTokenFromEnv() (string, error) {
	tokens, err := LoadTokensFromEnv()
	if err != nil {
		return "", err
	}
	return tokens[0], nil
}

// LoadTokensFromEnv reads the accepted token set (Issue #179 dual-trust).
//
// Sources (union, deduped, order preserved):
//  1. NEUROMESH_POLICY_BUNDLE_TOKEN_FILE — newline-separated tokens (preferred)
//  2. Sibling file "token-previous" next to TOKEN_FILE when that basename is "token"
//     or "accepted" (optional dual-accept without a second env)
//  3. NEUROMESH_POLICY_BUNDLE_TOKEN_PREVIOUS_FILE — explicit previous-token path
//  4. NEUROMESH_POLICY_BUNDLE_TOKEN — single lab env token when no file is set
//
// Empty after trim → error (fail-closed).
func LoadTokensFromEnv() ([]string, error) {
	var tokens []string

	if path := strings.TrimSpace(os.Getenv(EnvPolicyBundleTokenFile)); path != "" {
		path = filepath.Clean(path)
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("%s must be an absolute path, got %q", EnvPolicyBundleTokenFile, path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s (%q): %w", EnvPolicyBundleTokenFile, path, err)
		}
		tokens = append(tokens, splitTokenFile(string(raw))...)

		// Auto-load sibling token-previous when operators project both Secret keys
		// into the same directory (runbook dual-accept window).
		base := filepath.Base(path)
		if base == "token" || base == "accepted" {
			sib := filepath.Join(filepath.Dir(path), "token-previous")
			if prev, err := readOptionalTokenFile(sib); err != nil {
				return nil, err
			} else if prev != "" {
				tokens = append(tokens, prev)
			}
		}
	}

	if prevPath := strings.TrimSpace(os.Getenv(EnvPolicyBundleTokenPreviousFile)); prevPath != "" {
		prevPath = filepath.Clean(prevPath)
		if !filepath.IsAbs(prevPath) {
			return nil, fmt.Errorf("%s must be an absolute path, got %q", EnvPolicyBundleTokenPreviousFile, prevPath)
		}
		prev, err := readOptionalTokenFile(prevPath)
		if err != nil {
			return nil, fmt.Errorf("read %s (%q): %w", EnvPolicyBundleTokenPreviousFile, prevPath, err)
		}
		if prev == "" {
			return nil, fmt.Errorf("%s (%q) is empty", EnvPolicyBundleTokenPreviousFile, prevPath)
		}
		tokens = append(tokens, prev)
	}

	if len(tokens) == 0 {
		token := strings.TrimSpace(os.Getenv(EnvPolicyBundleToken))
		if token == "" {
			return nil, fmt.Errorf(
				"policy-bundle auth required: set %s or %s (Issue #55 / #179)",
				EnvPolicyBundleToken,
				EnvPolicyBundleTokenFile,
			)
		}
		tokens = []string{token}
	}

	tokens = dedupeTokens(tokens)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("policy-bundle accepted token set is empty after trim")
	}
	return tokens, nil
}

func readOptionalTokenFile(path string) (string, error) {
	// filepath.Clean + absolute-path gate: same pattern as LoadTokensFromEnv /
	// Cosign pubkey load — what gosec G304 recognizes for operator-configured paths.
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("token file path must be absolute, got %q", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func splitTokenFile(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func dedupeTokens(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

// matchBearerToken compares the presented bearer against every accepted token
// without early-exit on match (Issue #179).
//
// Each candidate uses SHA-256 then subtle.ConstantTimeCompare (fixed 32-byte
// digests). Results are OR-combined and the matching fingerprint is selected
// with subtle.ConstantTimeCopy so wall-clock time does not depend on *which*
// accepted token matched — only on the (ops-public) accepted-set size.
//
// Returns ok=false when no candidate matches. On failure, fingerprint is empty
// (never label metrics with a hash of an *invalid* presented secret — that
// would create an attacker-controlled cardinality oracle).
func matchBearerToken(presented string, accepted []string) (fingerprint string, ok bool) {
	if presented == "" || len(accepted) == 0 {
		return "", false
	}
	gotSum := sha256.Sum256([]byte(presented))
	var found int
	outFP := make([]byte, TokenFingerprintHexLen)

	for _, tok := range accepted {
		expSum := sha256.Sum256([]byte(tok))
		eq := subtle.ConstantTimeCompare(gotSum[:], expSum[:])
		found |= eq
		fp := []byte(TokenFingerprint(tok))
		if len(fp) != TokenFingerprintHexLen {
			// Defensive: TokenFingerprint length is a package invariant.
			return "", false
		}
		subtle.ConstantTimeCopy(eq, outFP, fp)
	}

	if found != 1 {
		return "", false
	}
	return string(outFP), true
}

// authorizeBearer checks Authorization: Bearer <token> against the accepted set.
// On success, records policy_bundle_auth_accept_total{fp="..."}.
func authorizeBearer(r *http.Request, accepted []string) bool {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	fp, ok := matchBearerToken(got, accepted)
	if !ok {
		return false
	}
	RecordAuthAccept(fp)
	return true
}
