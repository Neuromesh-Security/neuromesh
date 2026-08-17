package neuromesh.execution

import future.keywords.if
import future.keywords.in

# Default deny — Zero Trust posture.
default allow := false

# DesiredPolicy content (Issue #137): injected via OPA store at
# data.neuromesh.desired — same source as GET /v1/policy-bundle when dynamic
# mode is enabled. Bootstrap values are loaded at startup when Active() is nil.
desired := data.neuromesh.desired

deny_prefixes := desired.deny_path_prefixes
spiffe_ids := desired.spiffe_ids
scope_prefix := desired.identity_exception_scope_prefix

# Non-ephemeral execution is always permitted.
allow if {
	not ephemeral_execution
}

# Identity exception is scoped ONLY to scope_prefix (threat-model lock: /tmp/).
# Whitelisted SPIFFE IDs still cannot execute from other deny prefixes.
allow if {
	tmp_exception_scope
	identity_whitelisted
}

# Ephemeral = path matches any centrally-governed deny prefix.
ephemeral_execution if {
	some prefix in deny_prefixes
	startswith(input.binary_path, prefix)
}

tmp_exception_scope if {
	startswith(input.binary_path, scope_prefix)
}

identity_whitelisted if {
	input.identity in spiffe_ids
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
