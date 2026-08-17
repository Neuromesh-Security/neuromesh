package desiredpolicy

import (
	"reflect"
	"testing"

	"neuromesh/zt-policy-engine/internal/policybundle"
)

func TestRegoDataFromActiveUsesBootstrapWhenInactive(t *testing.T) {
	t.Cleanup(ClearForTest)

	data := RegoDataFromActive()
	if !reflect.DeepEqual(data.DenyPathPrefixes, policybundle.BootstrapDenyPathPrefixes) {
		t.Fatalf("deny prefixes: %v", data.DenyPathPrefixes)
	}
	if !reflect.DeepEqual(data.SpiffeIDs, policybundle.BootstrapIdentityAllowSPIFFEIDS) {
		t.Fatalf("spiffe ids: %v", data.SpiffeIDs)
	}
	if data.IdentityExceptionScopePrefix != policybundle.IdentityExceptionScopePrefix {
		t.Fatalf("scope: %q", data.IdentityExceptionScopePrefix)
	}
}

func TestRegoDataFromActiveUsesSnapshotWhenActive(t *testing.T) {
	t.Cleanup(ClearForTest)

	snap := Snapshot{
		DenyPathPrefixes: []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/opt/staging/"},
		SpiffeIDs:        []string{"spiffe://neuromesh.security/ns/default/sa/custom"},
		ScopePathPrefix:  DefaultIdentityExceptionScopePrefix,
	}
	if err := ApplyValidated(snap); err != nil {
		t.Fatalf("ApplyValidated: %v", err)
	}

	data := RegoDataFromActive()
	if len(data.DenyPathPrefixes) != 4 || data.DenyPathPrefixes[3] != "/opt/staging/" {
		t.Fatalf("deny prefixes: %v", data.DenyPathPrefixes)
	}
	if len(data.SpiffeIDs) != 1 || data.SpiffeIDs[0] != snap.SpiffeIDs[0] {
		t.Fatalf("spiffe ids: %v", data.SpiffeIDs)
	}
}
