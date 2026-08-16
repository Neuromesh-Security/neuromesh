package policybundle

import "sync/atomic"

// DesiredOverride is the optional Issue #137 PR-1 content source for CurrentAt.
// When nil (default), CurrentAt uses BootstrapDenyPathPrefixes /
// BootstrapIdentityAllowSPIFFEIDS — production posture until DesiredPolicy is
// explicitly enabled AND a valid ConfigMap has been applied.
type DesiredOverride struct {
	DenyPathPrefixes []string
	SpiffeIDs        []string
	ScopePathPrefix  string
}

var desiredOverride atomic.Pointer[DesiredOverride]

// SetDesiredOverride publishes (or clears) the DesiredPolicy-driven content.
// Called only from desiredpolicy after validation. Passing nil restores bootstrap.
func SetDesiredOverride(o *DesiredOverride) {
	if o == nil {
		desiredOverride.Store(nil)
		return
	}
	cp := &DesiredOverride{
		DenyPathPrefixes: append([]string(nil), o.DenyPathPrefixes...),
		SpiffeIDs:        append([]string(nil), o.SpiffeIDs...),
		ScopePathPrefix:  o.ScopePathPrefix,
	}
	desiredOverride.Store(cp)
}

func loadDesiredOverride() *DesiredOverride {
	p := desiredOverride.Load()
	if p == nil {
		return nil
	}
	return &DesiredOverride{
		DenyPathPrefixes: append([]string(nil), p.DenyPathPrefixes...),
		SpiffeIDs:        append([]string(nil), p.SpiffeIDs...),
		ScopePathPrefix:  p.ScopePathPrefix,
	}
}
