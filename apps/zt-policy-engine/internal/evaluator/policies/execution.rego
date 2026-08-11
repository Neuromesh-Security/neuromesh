package neuromesh.execution

import future.keywords.if
import future.keywords.in

# Default deny — Zero Trust posture.
default allow := false

# Internal Neuromesh workloads permitted to stage artifacts in /tmp/ ONLY.
# Phase 2 kernel identity exceptions match this scope:
# /tmp/ may be excepted for whitelisted SPIFFE IDs; /dev/shm/ and /var/tmp/
# remain hard-denied in the LSM (and here) regardless of identity. Widening
# that set is a deliberate Rego + threat-model policy change — not an
# implementation side effect.
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
	not ephemeral_execution
}

# Identity exception is scoped ONLY to /tmp/ (matches kernel LSM lock).
# Whitelisted SPIFFE IDs still cannot execute from /dev/shm/ or /var/tmp/.
allow if {
	tmp_exception_scope
	identity_whitelisted
}

# All three PATH_DENY_LIST bootstrap prefixes — control-plane must match
# kernel deny surface. Prior bug: only /tmp/ was checked, so
# `allow if { not tmp_execution }` incorrectly allowed /dev/shm/ and /var/tmp/.
ephemeral_execution if {
	startswith(input.binary_path, "/tmp/")
}

ephemeral_execution if {
	startswith(input.binary_path, "/dev/shm/")
}

ephemeral_execution if {
	startswith(input.binary_path, "/var/tmp/")
}

tmp_exception_scope if {
	startswith(input.binary_path, "/tmp/")
}

identity_whitelisted if {
	input.identity in whitelist
}

deny_reason := "execution from ephemeral staging path /tmp/ requires whitelisted identity" if {
	tmp_exception_scope
	not identity_whitelisted
}

deny_reason := "execution from ephemeral staging path is hard-denied (no identity exception)" if {
	ephemeral_execution
	not tmp_exception_scope
}

deny_reason := "" if {
	allow
}
