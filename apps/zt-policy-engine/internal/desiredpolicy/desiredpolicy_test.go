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
	if !snap.AllowFloorPrefixRemoval {
		t.Fatal("AllowFloorPrefixRemoval must be recorded on snapshot")
	}
	if len(snap.FloorPrefixesAbsent) != 1 || snap.FloorPrefixesAbsent[0] != "/var/tmp/" {
		t.Fatalf("FloorPrefixesAbsent: %v", snap.FloorPrefixesAbsent)
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
	if err := ApplyValidated(snap); err != nil {
		t.Fatalf("ApplyValidated: %v", err)
	}

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
	if err := ApplyValidated(good); err != nil {
		t.Fatalf("ApplyValidated: %v", err)
	}
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

func TestFloorRemovalSafetyRailOverrideLogging(t *testing.T) {
	t.Cleanup(ClearForTest)

	idBlock := `"identity_allow_exceptions":{"scope_path_prefix":"/tmp/","spiffe_ids":["spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"]}`

	t.Run("a_rejected_without_override", func(t *testing.T) {
		t.Cleanup(ClearForTest)
		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(prev) })

		raw := mustCMJSON(t, "10", `{
  "deny_path_prefixes": ["/tmp/", "/dev/shm/"],
  `+idBlock+`
}`)
		if err := ApplyConfigMapJSON(raw); err == nil {
			t.Fatal("expected rejection without allow_floor_prefix_removal")
		}
		out := buf.String()
		if !strings.Contains(out, "desired_policy_rejected") {
			t.Fatalf("expected rejected audit, got:\n%s", out)
		}
		if strings.Contains(out, "desired_policy_SAFETY_RAIL_OVERRIDE") {
			t.Fatalf("rejected apply must not emit SAFETY_RAIL_OVERRIDE:\n%s", out)
		}
		if strings.Contains(out, "desired_policy_accepted") {
			t.Fatalf("rejected apply must not emit accepted:\n%s", out)
		}
	})

	t.Run("b_override_emits_accepted_and_safety_rail", func(t *testing.T) {
		t.Cleanup(ClearForTest)
		// Establish LKG with all three floors first.
		if err := ApplyConfigMapJSON(mustCMJSON(t, "20", `{
  "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
  `+idBlock+`
}`)); err != nil {
			t.Fatalf("seed LKG: %v", err)
		}

		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(prev) })

		raw := mustCMJSON(t, "21", `{
  "deny_path_prefixes": ["/tmp/", "/dev/shm/"],
  "allow_floor_prefix_removal": true,
  `+idBlock+`
}`)
		if err := ApplyConfigMapJSON(raw); err != nil {
			t.Fatalf("ApplyConfigMapJSON: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "desired_policy_accepted") {
			t.Fatalf("expected accepted log:\n%s", out)
		}
		if !strings.Contains(out, "desired_policy_SAFETY_RAIL_OVERRIDE") {
			t.Fatalf("expected SAFETY_RAIL_OVERRIDE log:\n%s", out)
		}
		if !strings.Contains(out, `severity=WARNING`) {
			t.Fatalf("expected WARNING severity on override line:\n%s", out)
		}
		if !strings.Contains(out, `floor_prefixes_removed="/var/tmp/"`) &&
			!strings.Contains(out, `floor_prefixes_removed="/var/tmp/`) {
			t.Fatalf("expected /var/tmp/ in floor_prefixes_removed:\n%s", out)
		}
		if !strings.Contains(out, `resource_version="21"`) {
			t.Fatalf("override line must carry resource_version:\n%s", out)
		}
		// Accepted must appear before (or at least separately from) override tag.
		accIdx := strings.Index(out, "desired_policy_accepted")
		ovrIdx := strings.Index(out, "desired_policy_SAFETY_RAIL_OVERRIDE")
		if accIdx < 0 || ovrIdx < 0 || ovrIdx < accIdx {
			t.Fatalf("SAFETY_RAIL_OVERRIDE must be a separate line after accepted:\n%s", out)
		}
	})

	t.Run("c_normal_change_no_false_positive", func(t *testing.T) {
		t.Cleanup(ClearForTest)
		if err := ApplyConfigMapJSON(mustCMJSON(t, "30", `{
  "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
  `+idBlock+`
}`)); err != nil {
			t.Fatalf("seed: %v", err)
		}

		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		t.Cleanup(func() { log.SetOutput(prev) })

		// Widen SPIFFE allowlist; floors untouched. Even with override flag true,
		// no floor is removed → no SAFETY_RAIL_OVERRIDE.
		raw := mustCMJSON(t, "31", `{
  "deny_path_prefixes": ["/tmp/", "/dev/shm/", "/var/tmp/"],
  "allow_floor_prefix_removal": true,
  "identity_allow_exceptions": {
    "scope_path_prefix": "/tmp/",
    "spiffe_ids": [
      "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
      "spiffe://neuromesh.security/ns/default/sa/extra-workload"
    ]
  }
}`)
		if err := ApplyConfigMapJSON(raw); err != nil {
			t.Fatalf("ApplyConfigMapJSON: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "desired_policy_accepted") {
			t.Fatalf("expected accepted:\n%s", out)
		}
		if strings.Contains(out, "desired_policy_SAFETY_RAIL_OVERRIDE") {
			t.Fatalf("false positive SAFETY_RAIL_OVERRIDE:\n%s", out)
		}
	})
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
