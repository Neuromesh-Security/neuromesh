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
//! Unauthenticated or invalid credentials are rejected. There is no
//! unauthenticated fallback path.
package policybundle

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	// EnvPolicyBundleToken is the shared bearer token (plaintext env — prefer file in prod).
	EnvPolicyBundleToken = "NEUROMESH_POLICY_BUNDLE_TOKEN"
	// EnvPolicyBundleTokenFile is an absolute path to a file containing the token
	// (Kubernetes Secret mount pattern, mirrors Cosign pubkey delivery).
	EnvPolicyBundleTokenFile = "NEUROMESH_POLICY_BUNDLE_TOKEN_FILE"
)

// LoadTokenFromEnv reads the shared token from file (preferred) or env.
// Returns an error if neither is set or the value is empty after trim —
// the server must fail closed rather than serve the bundle without auth.
func LoadTokenFromEnv() (string, error) {
	if path := strings.TrimSpace(os.Getenv(EnvPolicyBundleTokenFile)); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s (%q): %w", EnvPolicyBundleTokenFile, path, err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", fmt.Errorf("%s (%q) is empty", EnvPolicyBundleTokenFile, path)
		}
		return token, nil
	}
	token := strings.TrimSpace(os.Getenv(EnvPolicyBundleToken))
	if token == "" {
		return "", fmt.Errorf(
			"policy-bundle auth required: set %s or %s (Issue #55)",
			EnvPolicyBundleToken,
			EnvPolicyBundleTokenFile,
		)
	}
	return token, nil
}

// authorizeBearer checks Authorization: Bearer <token> with constant-time compare
// of SHA-256 digests so token length is not leaked via early exit on size mismatch
// of the raw secrets (both sides hashed to fixed 32 bytes first).
func authorizeBearer(r *http.Request, expectedToken string) bool {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if got == "" || expectedToken == "" {
		return false
	}
	gotSum := sha256.Sum256([]byte(got))
	expSum := sha256.Sum256([]byte(expectedToken))
	return subtle.ConstantTimeCompare(gotSum[:], expSum[:]) == 1
}
