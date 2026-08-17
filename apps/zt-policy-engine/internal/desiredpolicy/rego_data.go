package desiredpolicy

import (
	"neuromesh/zt-policy-engine/internal/policybundle"
)

// RegoData is the OPA store document for neuromesh.execution (Issue #137 PR-2).
// Same content fields as policybundle.CurrentAt / DesiredOverride.
type RegoData struct {
	DenyPathPrefixes               []string
	SpiffeIDs                      []string
	IdentityExceptionScopePrefix   string
}

// RegoDataFromActive returns the Rego store payload from the LKG DesiredPolicy
// snapshot, or policybundle bootstrap constants when inactive (nil Active) —
// one bootstrap truth shared with the bundle plane.
func RegoDataFromActive() RegoData {
	if snap := Active(); snap != nil {
		return RegoDataFromSnapshot(*snap)
	}
	return bootstrapRegoData()
}

// RegoDataFromSnapshot builds Rego data from a validated snapshot.
func RegoDataFromSnapshot(snap Snapshot) RegoData {
	return RegoData{
		DenyPathPrefixes:             append([]string(nil), snap.DenyPathPrefixes...),
		SpiffeIDs:                    append([]string(nil), snap.SpiffeIDs...),
		IdentityExceptionScopePrefix: snap.ScopePathPrefix,
	}
}

func bootstrapRegoData() RegoData {
	return RegoData{
		DenyPathPrefixes:             append([]string(nil), policybundle.BootstrapDenyPathPrefixes...),
		SpiffeIDs:                    append([]string(nil), policybundle.BootstrapIdentityAllowSPIFFEIDS...),
		IdentityExceptionScopePrefix: policybundle.IdentityExceptionScopePrefix,
	}
}

// StoreDocument returns the in-memory OPA store root object for PrepareForEval.
func (d RegoData) StoreDocument() map[string]interface{} {
	prefixes := make([]interface{}, len(d.DenyPathPrefixes))
	for i, p := range d.DenyPathPrefixes {
		prefixes[i] = p
	}
	ids := make([]interface{}, len(d.SpiffeIDs))
	for i, id := range d.SpiffeIDs {
		ids[i] = id
	}
	return map[string]interface{}{
		"neuromesh": map[string]interface{}{
			"desired": map[string]interface{}{
				"deny_path_prefixes":                prefixes,
				"spiffe_ids":                        ids,
				"identity_exception_scope_prefix":   d.IdentityExceptionScopePrefix,
			},
		},
	}
}
