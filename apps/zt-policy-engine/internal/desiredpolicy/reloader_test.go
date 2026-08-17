package desiredpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"neuromesh/zt-policy-engine/internal/policybundle"
)

type failRegoReloader struct{}

func (failRegoReloader) Reload(context.Context, RegoData) error {
	return errors.New("simulated rego reload failure")
}

func TestApplyValidatedReloadFailureRetainsLKG(t *testing.T) {
	t.Cleanup(func() {
		ClearForTest()
		ClearRegoReloaderForTest()
	})

	good := mustValidate(t, Document{
		DenyPathPrefixes: append([]string(nil), FloorDenyPathPrefixes...),
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: DefaultIdentityExceptionScopePrefix,
			SpiffeIDs:       []string{"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"},
		},
	})
	if err := ApplyValidated(good); err != nil {
		t.Fatalf("seed ApplyValidated: %v", err)
	}
	beforeVersion := policybundle.CurrentAt(time.Now().UTC()).Version

	SetRegoReloader(failRegoReloader{})

	bad := good
	bad.DenyPathPrefixes = append(append([]string(nil), FloorDenyPathPrefixes...), "/opt/staging/")
	bad.ContentVersion = "sha256:should-not-land"
	if err := ApplyValidated(bad); err == nil {
		t.Fatal("expected reload failure")
	}

	after := Active()
	if after == nil || after.ContentVersion != good.ContentVersion {
		t.Fatalf("store LKG changed: %+v", after)
	}
	if policybundle.CurrentAt(time.Now().UTC()).Version != beforeVersion {
		t.Fatal("bundle plane changed after failed reload")
	}
}
