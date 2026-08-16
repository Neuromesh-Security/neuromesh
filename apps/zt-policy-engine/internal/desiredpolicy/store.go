package desiredpolicy

import (
	"sync/atomic"

	"neuromesh/zt-policy-engine/internal/policybundle"
)

// global holds the last-known-good validated snapshot (nil = use compile-time bootstrap).
var global atomic.Pointer[Snapshot]

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

// ApplyValidated stores snap as LKG and publishes it into policybundle so
// CurrentAt() serves the new content on the next GET (sign+timestamp unchanged).
func ApplyValidated(snap Snapshot) {
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
}

// ClearForTest resets LKG + policybundle override (unit tests only).
func ClearForTest() {
	global.Store(nil)
	policybundle.SetDesiredOverride(nil)
}
