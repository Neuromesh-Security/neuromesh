package desiredpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Validate checks anti-weaken + structural rules. On success returns a Snapshot
// (ContentVersion filled; ResourceVersion left empty for the caller to set).
func Validate(doc Document) (Snapshot, error) {
	if len(doc.DenyPathPrefixes) == 0 {
		return Snapshot{}, fmt.Errorf("deny_path_prefixes is empty (refusing fail-open)")
	}
	if len(doc.DenyPathPrefixes) > MaxDenyPathPrefixes {
		return Snapshot{}, fmt.Errorf(
			"deny_path_prefixes has %d entries; max is %d",
			len(doc.DenyPathPrefixes), MaxDenyPathPrefixes,
		)
	}
	seenPrefix := make(map[string]struct{}, len(doc.DenyPathPrefixes))
	prefixes := make([]string, 0, len(doc.DenyPathPrefixes))
	for i, p := range doc.DenyPathPrefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			return Snapshot{}, fmt.Errorf("deny_path_prefixes[%d] is empty", i)
		}
		if !strings.HasPrefix(p, "/") {
			return Snapshot{}, fmt.Errorf("deny_path_prefixes[%d] %q must be absolute", i, p)
		}
		if _, dup := seenPrefix[p]; dup {
			return Snapshot{}, fmt.Errorf("deny_path_prefixes duplicate %q", p)
		}
		seenPrefix[p] = struct{}{}
		prefixes = append(prefixes, p)
	}

	var floorsAbsent []string
	for _, floor := range FloorDenyPathPrefixes {
		if _, ok := seenPrefix[floor]; !ok {
			floorsAbsent = append(floorsAbsent, floor)
		}
	}
	if len(floorsAbsent) > 0 && !doc.AllowFloorPrefixRemoval {
		return Snapshot{}, fmt.Errorf(
			"floor deny prefix %q missing (set allow_floor_prefix_removal=true to override)",
			floorsAbsent[0],
		)
	}

	if doc.IdentityAllowExceptions == nil {
		return Snapshot{}, fmt.Errorf("identity_allow_exceptions is required")
	}
	scope := strings.TrimSpace(doc.IdentityAllowExceptions.ScopePathPrefix)
	if scope == "" {
		return Snapshot{}, fmt.Errorf("identity_allow_exceptions.scope_path_prefix is empty")
	}
	if scope != DefaultIdentityExceptionScopePrefix {
		return Snapshot{}, fmt.Errorf(
			"identity_allow_exceptions.scope_path_prefix %q must be %q (threat-model lock)",
			scope, DefaultIdentityExceptionScopePrefix,
		)
	}
	if len(doc.IdentityAllowExceptions.SpiffeIDs) > MaxSpiffeIDs {
		return Snapshot{}, fmt.Errorf(
			"spiffe_ids has %d entries; max is %d",
			len(doc.IdentityAllowExceptions.SpiffeIDs), MaxSpiffeIDs,
		)
	}
	seenID := make(map[string]struct{}, len(doc.IdentityAllowExceptions.SpiffeIDs))
	ids := make([]string, 0, len(doc.IdentityAllowExceptions.SpiffeIDs))
	for i, id := range doc.IdentityAllowExceptions.SpiffeIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return Snapshot{}, fmt.Errorf("spiffe_ids[%d] is empty", i)
		}
		if !strings.HasPrefix(id, "spiffe://") {
			return Snapshot{}, fmt.Errorf("spiffe_ids[%d] %q must be a spiffe:// URI", i, id)
		}
		if !strings.Contains(id, "/ns/") || !strings.Contains(id, "/sa/") {
			return Snapshot{}, fmt.Errorf(
				"spiffe_ids[%d] %q must be path-form (/ns/.../sa/...)", i, id,
			)
		}
		if _, dup := seenID[id]; dup {
			return Snapshot{}, fmt.Errorf("spiffe_ids duplicate %q", id)
		}
		seenID[id] = struct{}{}
		ids = append(ids, id)
	}

	return Snapshot{
		DenyPathPrefixes:        prefixes,
		SpiffeIDs:               ids,
		ScopePathPrefix:         scope,
		ContentVersion:          contentVersion(prefixes, ids, scope),
		AllowFloorPrefixRemoval: doc.AllowFloorPrefixRemoval,
		FloorPrefixesAbsent:     floorsAbsent,
	}, nil
}

// contentVersion mirrors policybundle.contentVersion so audit/version strings match.
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
