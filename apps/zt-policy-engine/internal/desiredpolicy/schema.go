package desiredpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ConfigMapDataKey is the ConfigMap `.data` entry that holds the DesiredPolicy JSON.
const ConfigMapDataKey = "policy.json"

// MaxDenyPathPrefixes matches neuromesh-common PATH_DENY_MAX_ENTRIES.
const MaxDenyPathPrefixes = 64

// MaxSpiffeIDs caps identity_allow_exceptions.spiffe_ids (fail-closed).
const MaxSpiffeIDs = 256

// FloorDenyPathPrefixes must remain present unless AllowFloorPrefixRemoval is set.
// Identical to policybundle.BootstrapDenyPathPrefixes (duplicated here so
// validation does not import policybundle and create a cycle risk with tests).
var FloorDenyPathPrefixes = []string{
	"/tmp/",
	"/dev/shm/",
	"/var/tmp/",
}

// DefaultIdentityExceptionScopePrefix matches policybundle.IdentityExceptionScopePrefix.
const DefaultIdentityExceptionScopePrefix = "/tmp/"

// Document is the ConfigMap policy.json schema for Issue #137 PR-1.
// Field names/types match the agent-facing bundle body subsets that
// policybundle.CurrentAt stamps into deny_path_prefixes + identity_allow_exceptions
// (timestamps / not_before / not_after are NOT operator-supplied — still minted
// by CurrentAt on each GET).
type Document struct {
	DenyPathPrefixes          []string                   `json:"deny_path_prefixes"`
	IdentityAllowExceptions   *IdentityAllowExceptions   `json:"identity_allow_exceptions"`
	AllowFloorPrefixRemoval   bool                       `json:"allow_floor_prefix_removal,omitempty"`
}

// IdentityAllowExceptions mirrors the bundle identity section content fields
// (scope + spiffe_ids). issued_at / expires_at are server-minted.
type IdentityAllowExceptions struct {
	ScopePathPrefix string   `json:"scope_path_prefix"`
	SpiffeIDs       []string `json:"spiffe_ids"`
}

// Snapshot is a validated DesiredPolicy ready to drive CurrentAt.
type Snapshot struct {
	DenyPathPrefixes []string
	SpiffeIDs        []string
	ScopePathPrefix  string
	ContentVersion   string // sha256:… matching policybundle contentVersion formula
	ResourceVersion  string // ConfigMap metadata.resourceVersion (audit)
	// AllowFloorPrefixRemoval echoes the operator flag that permitted missing floors.
	AllowFloorPrefixRemoval bool
	// FloorPrefixesAbsent lists floor prefixes missing from DenyPathPrefixes
	// (non-empty only when AllowFloorPrefixRemoval was true at validate time).
	FloorPrefixesAbsent []string
}

// ParseDocument unmarshals policy.json bytes (unknown fields rejected).
func ParseDocument(raw []byte) (Document, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("desired policy JSON: %w", err)
	}
	return doc, nil
}
