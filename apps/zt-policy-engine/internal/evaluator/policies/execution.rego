package neuromesh.execution

import future.keywords.if
import future.keywords.in

# Default deny — Zero Trust posture.
default allow := false

# Internal Neuromesh workloads permitted to stage artifacts in /tmp/.
# Phase 2 kernel identity exceptions (when wired) match this scope ONLY:
# /tmp/ may be excepted for whitelisted SPIFFE IDs; /dev/shm/ and /var/tmp/
# remain hard-denied in the LSM regardless of identity. Widening that set is
# a deliberate Rego + threat-model policy change — not an implementation side effect.
#
# IDs are path-form (SPIRE K8s canonical): spiffe://{trust}/ns/{ns}/sa/{sa}.
# Flat shorthand (spiffe://trust/name) is intentionally rejected.
whitelist := {
	"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
	"spiffe://neuromesh.security/ns/default/sa/zt-policy-engine",
	"spiffe://neuromesh.security/ns/default/sa/ai-threat-detector",
}

# Non-ephemeral execution is always permitted.
allow if {
	not tmp_execution
}

# Ephemeral /tmp/ execution requires a whitelisted SPIFFE identity.
allow if {
	tmp_execution
	identity_whitelisted
}

tmp_execution if {
	startswith(input.binary_path, "/tmp/")
}

identity_whitelisted if {
	input.identity in whitelist
}

deny_reason := "execution from ephemeral staging path /tmp/ requires whitelisted identity" if {
	tmp_execution
	not identity_whitelisted
}

deny_reason := "" if {
	allow
}
