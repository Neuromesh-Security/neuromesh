//! DesiredPolicy — Issue #137 PR-1 (bundle plane only).
//!
//! ConfigMap-backed desired deny prefixes + identity SPIFFE allowlist for
//! GET /v1/policy-bundle. Rego (/v1/evaluate) is intentionally NOT fed here
//! (PR-2). Production must keep NEUROMESH_DESIRED_POLICY_ENABLE unset until
//! PR-2 ships — see enable.go and deploy manifests.
package desiredpolicy
