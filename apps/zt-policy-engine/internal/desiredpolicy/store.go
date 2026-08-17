package desiredpolicy

import (
	"context"
	"sync"
	"sync/atomic"

	"neuromesh/zt-policy-engine/internal/policybundle"
)

// global holds the last-known-good validated snapshot (nil = use compile-time bootstrap).
var global atomic.Pointer[Snapshot]

// applyMu serializes bundle + Rego plane updates (Issue #137 PR-2).
var applyMu sync.Mutex

// Active returns a copy of the LKG DesiredPolicy snapshot, or nil when the
// feature is inactive / never successfully applied (CurrentAt uses bootstrap).
func Active() *Snapshot {
	p := global.Load()
	if p == nil {
		return nil
	}
	cp := *p
	cp.DenyPathPrefixes = append([]string(nil), p.DenyPathPrefixes...)
	cp.SpiffeIDs = append([]string(nil), p.SpiffeIDs...)
	cp.FloorPrefixesAbsent = append([]string(nil), p.FloorPrefixesAbsent...)
	return &cp
}

// ApplyValidated stores snap as LKG and publishes it into policybundle and Rego.
// Rego reload runs first; on failure LKG is unchanged on both planes.
func ApplyValidated(snap Snapshot) error {
	applyMu.Lock()
	defer applyMu.Unlock()

	data := RegoDataFromSnapshot(snap)
	if err := reloadRego(context.Background(), data); err != nil {
		return err
	}

	cp := snap
	cp.DenyPathPrefixes = append([]string(nil), snap.DenyPathPrefixes...)
	cp.SpiffeIDs = append([]string(nil), snap.SpiffeIDs...)
	cp.FloorPrefixesAbsent = append([]string(nil), snap.FloorPrefixesAbsent...)
	global.Store(&cp)
	policybundle.SetDesiredOverride(&policybundle.DesiredOverride{
		DenyPathPrefixes: cp.DenyPathPrefixes,
		SpiffeIDs:        cp.SpiffeIDs,
		ScopePathPrefix:  cp.ScopePathPrefix,
	})
	return nil
}

// ClearForTest resets LKG + policybundle override (unit tests only).
func ClearForTest() {
	applyMu.Lock()
	defer applyMu.Unlock()
	global.Store(nil)
	policybundle.SetDesiredOverride(nil)
}
