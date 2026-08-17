// Package desiredpolicy implements ConfigMap-backed DesiredPolicy (Issue #137).
//
// ConfigMap-backed desired deny prefixes + identity SPIFFE allowlist feeds
// GET /v1/policy-bundle (via policybundle.CurrentAt) and POST /v1/evaluate
// (via OPA store data.neuromesh.desired). Production remains default-off until
// NEUROMESH_DESIRED_POLICY_ENABLE + NEUROMESH_DESIRED_POLICY_CONFIGMAP are set.
package desiredpolicy
