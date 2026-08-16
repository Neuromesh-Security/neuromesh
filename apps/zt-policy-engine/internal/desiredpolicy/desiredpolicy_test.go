package desiredpolicy

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"

	"neuromesh/zt-policy-engine/internal/policybundle"
)

func TestValidateRejectsEmptyDeny(t *testing.T) {
	t.Cleanup(ClearForTest)
	_, err := Validate(Document{
		DenyPathPrefixes: nil,
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: DefaultIdentityExceptionScopePrefix,
			SpiffeIDs:       []string{"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty deny rejection, got %v", err)
	}
}

func TestValidateRejectsFloorRemovalWithoutOverride(t *testing.T) {
	t.Cleanup(ClearForTest)
	_, err := Validate(Document{
		DenyPathPrefixes: []string{"/tmp/", "/dev/shm/"}, // missing /var/tmp/
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: DefaultIdentityExceptionScopePrefix,
			SpiffeIDs:       []string{"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "/var/tmp/") {
		t.Fatalf("expected floor rejection, got %v", err)
	}
}

func TestValidateAllowsFloorRemovalWithOverride(t *testing.T) {
	t.Cleanup(ClearForTest)
	snap, err := Validate(Document{
		DenyPathPrefixes:        []string{"/tmp/", "/dev/shm/"},
		AllowFloorPrefixRemoval: true,
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: DefaultIdentityExceptionScopePrefix,
			SpiffeIDs:       []string{"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"},
		},
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(snap.DenyPathPrefixes) != 2 {
		t.Fatalf("prefixes: %v", snap.DenyPathPrefixes)
	}
}

func TestValidateRejectsWrongScope(t *testing.T) {
	t.Cleanup(ClearForTest)
	_, err := Validate(Document{
		DenyPathPrefixes: append([]string(nil), FloorDenyPathPrefixes...),
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: "/dev/shm/",
			SpiffeIDs:       []string{"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "scope_path_prefix") {
		t.Fatalf("expected scope rejection, got %v", err)
	}
}

func TestValidateRejectsFlatSpiffe(t *testing.T) {
	t.Cleanup(ClearForTest)
	_, err := Validate(Document{
		DenyPathPrefixes: append([]string(nil), FloorDenyPathPrefixes...),
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: DefaultIdentityExceptionScopePrefix,
			SpiffeIDs:       []string{"spiffe://neuromesh.security/agent-ebpf-sensor"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "path-form") {
		t.Fatalf("expected path-form rejection, got %v", err)
	}
}

func TestValidChangeReflectedInCurrentAt(t *testing.T) {
	t.Cleanup(ClearForTest)
	t.Setenv(policybundle.EnvPolicyBundleValiditySecs, "")

	extraID := "spiffe://neuromesh.security/ns/default/sa/extra-workload"
	doc := Document{
		DenyPathPrefixes: append([]string(nil), FloorDenyPathPrefixes...),
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: DefaultIdentityExceptionScopePrefix,
			SpiffeIDs: []string{
				"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
				extraID,
			},
		},
	}
	snap, err := Validate(doc)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	snap.ResourceVersion = "42"
	ApplyValidated(snap)

	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	b := policybundle.CurrentAt(now)
	if len(b.DenyPathPrefixes) != 3 {
		t.Fatalf("deny prefixes: %v", b.DenyPathPrefixes)
	}
	if b.IdentityAllowExceptions == nil || len(b.IdentityAllowExceptions.SpiffeIDs) != 2 {
		t.Fatalf("spiffe_ids: %+v", b.IdentityAllowExceptions)
	}
	found := false
	for _, id := range b.IdentityAllowExceptions.SpiffeIDs {
		if id == extraID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q in CurrentAt spiffe_ids", extraID)
	}
	if b.Version != snap.ContentVersion {
		t.Fatalf("version mismatch: bundle %q snap %q", b.Version, snap.ContentVersion)
	}
	if b.NotBefore != "2026-08-16T12:00:00Z" || b.NotAfter != "2026-08-16T12:05:00Z" {
		t.Fatalf("temporal: before=%q after=%q", b.NotBefore, b.NotAfter)
	}
}

func TestInvalidApplyRetainsLastKnownGood(t *testing.T) {
	t.Cleanup(ClearForTest)
	good := mustValidate(t, Document{
		DenyPathPrefixes: append([]string(nil), FloorDenyPathPrefixes...),
		IdentityAllowExceptions: &IdentityAllowExceptions{
			ScopePathPrefix: DefaultIdentityExceptionScopePrefix,
			SpiffeIDs:       []string{"spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"},
		},
	})
	ApplyValidated(good)
	before := policybundle.CurrentAt(time.Now().UTC()).Version

	raw := mustCMJSON(t, "99", `{
  "deny_path_prefixes": [],
  "identity_allow_exceptions": {
    "scope_path_prefix": "/tmp/",
    "spiffe_ids": []
  }
}`)
	if err := ApplyConfigMapJSON(raw); err == nil {
		t.Fatal("expected rejection of empty deny")
	}
	after := policybundle.CurrentAt(time.Now().UTC()).Version
	if before != after {
		t.Fatalf("LKG not retained: before %q after %q", before, after)
	}
	if Active() == nil || Active().ContentVersion != good.ContentVersion {
		t.Fatal("store LKG lost")
	}
}

func TestApplyConfigMapJSONAccepted(t *testing.T) {
	t.Cleanup(ClearForTest)
	policy := `{
  "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
  "identity_allow_exceptions": {
    "scope_path_prefix": "/tmp/",
    "spiffe_ids": ["spiffe://neuromesh.security/ns/default/sa/zt-policy-engine"]
  }
}`
	raw := mustCMJSON(t, "7", policy)
	if err := ApplyConfigMapJSON(raw); err != nil {
		t.Fatalf("ApplyConfigMapJSON: %v", err)
	}
	act := Active()
	if act == nil || act.ResourceVersion != "7" {
		t.Fatalf("active: %+v", act)
	}
	b := policybundle.CurrentAt(time.Now().UTC())
	if len(b.IdentityAllowExceptions.SpiffeIDs) != 1 {
		t.Fatalf("spiffe: %v", b.IdentityAllowExceptions.SpiffeIDs)
	}
}

func TestAuditAcceptedFormat(t *testing.T) {
	t.Cleanup(ClearForTest)
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	old := &Snapshot{
		DenyPathPrefixes: []string{"/tmp/", "/dev/shm/", "/var/tmp/"},
		SpiffeIDs:        []string{"spiffe://neuromesh.security/ns/default/sa/a"},
		ContentVersion:   "sha256:old",
	}
	neu := &Snapshot{
		DenyPathPrefixes: []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/opt/staging/"},
		SpiffeIDs: []string{
			"spiffe://neuromesh.security/ns/default/sa/a",
			"spiffe://neuromesh.security/ns/default/sa/b",
		},
		ContentVersion: "sha256:new",
	}
	AuditAccepted("123", old.ContentVersion, neu.ContentVersion, old, neu)
	line := buf.String()
	for _, want := range []string{
		"desired_policy_accepted",
		`resource_version="123"`,
		`old_content_version="sha256:old"`,
		`new_content_version="sha256:new"`,
		"prefixes_added=",
		"/opt/staging/",
		"spiffe_ids_added=",
		"/sa/b",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit line missing %q:\n%s", want, line)
		}
	}
}

func TestEnabledDualGate(t *testing.T) {
	t.Setenv(EnvDesiredPolicyEnable, "")
	t.Setenv(EnvDesiredPolicyConfigMap, "neuromesh-desired-policy")
	if Enabled() {
		t.Fatal("enable flag off → disabled")
	}
	t.Setenv(EnvDesiredPolicyEnable, "true")
	t.Setenv(EnvDesiredPolicyConfigMap, "")
	if Enabled() {
		t.Fatal("missing configmap name → disabled")
	}
	t.Setenv(EnvDesiredPolicyEnable, "true")
	t.Setenv(EnvDesiredPolicyConfigMap, "neuromesh-desired-policy")
	if !Enabled() {
		t.Fatal("both set → enabled")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := ParseDocument([]byte(`{"deny_path_prefixes":["/tmp/"],"extra":1}`))
	if err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func mustValidate(t *testing.T, doc Document) Snapshot {
	t.Helper()
	s, err := Validate(doc)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return s
}

func mustCMJSON(t *testing.T, rv, policyJSON string) []byte {
	t.Helper()
	type cm struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	var o cm
	o.Metadata.ResourceVersion = rv
	o.Data = map[string]string{ConfigMapDataKey: policyJSON}
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
