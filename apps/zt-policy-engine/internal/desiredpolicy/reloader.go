package desiredpolicy

import (
	"context"
	"sync"
)

// RegoReloader applies RegoData to the OPA evaluate plane (Issue #137 PR-2).
type RegoReloader interface {
	Reload(context.Context, RegoData) error
}

var (
	regoReloader   RegoReloader
	regoReloaderMu sync.RWMutex
)

// SetRegoReloader registers the OPA reload hook (wired from cmd/server at startup).
// Safe to call once before DesiredPolicy watch is enabled.
func SetRegoReloader(r RegoReloader) {
	regoReloaderMu.Lock()
	regoReloader = r
	regoReloaderMu.Unlock()
}

// ClearRegoReloaderForTest removes the reload hook (unit tests only).
func ClearRegoReloaderForTest() {
	SetRegoReloader(nil)
}

func reloadRego(ctx context.Context, data RegoData) error {
	regoReloaderMu.RLock()
	r := regoReloader
	regoReloaderMu.RUnlock()
	if r == nil {
		return nil
	}
	return r.Reload(ctx, data)
}
