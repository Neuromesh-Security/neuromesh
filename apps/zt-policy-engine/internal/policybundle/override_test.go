package policybundle

import (
	"testing"
	"time"
)

func TestDesiredOverrideChangesCurrentAtAndClearRestoresBootstrap(t *testing.T) {
	t.Cleanup(func() { SetDesiredOverride(nil) })
	t.Setenv(EnvPolicyBundleValiditySecs, "")

	base := CurrentAt(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if len(base.DenyPathPrefixes) != 3 {
		t.Fatalf("bootstrap prefixes: %v", base.DenyPathPrefixes)
	}

	SetDesiredOverride(&DesiredOverride{
		DenyPathPrefixes: []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/opt/x/"},
		SpiffeIDs:        []string{"spiffe://neuromesh.security/ns/default/sa/only-one"},
		ScopePathPrefix:  IdentityExceptionScopePrefix,
	})
	over := CurrentAt(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if len(over.DenyPathPrefixes) != 4 {
		t.Fatalf("override prefixes: %v", over.DenyPathPrefixes)
	}
	if len(over.IdentityAllowExceptions.SpiffeIDs) != 1 {
		t.Fatalf("override spiffe: %v", over.IdentityAllowExceptions.SpiffeIDs)
	}
	if over.Version == base.Version {
		t.Fatal("content version must change under override")
	}
	// Temporal fields still minted at CurrentAt time (sign cycle unchanged).
	if over.NotBefore != base.NotBefore {
		t.Fatalf("not_before should match same clock: %q vs %q", over.NotBefore, base.NotBefore)
	}

	SetDesiredOverride(nil)
	restored := CurrentAt(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if restored.Version != base.Version {
		t.Fatalf("clear must restore bootstrap version: got %q want %q", restored.Version, base.Version)
	}
}
