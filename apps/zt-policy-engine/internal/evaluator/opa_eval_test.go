package evaluator

import (
	"context"
	"testing"

	"neuromesh/zt-policy-engine/internal/policybundle"
)

func bootstrapStoreRoot() map[string]interface{} {
	prefixes := make([]interface{}, len(policybundle.BootstrapDenyPathPrefixes))
	for i, p := range policybundle.BootstrapDenyPathPrefixes {
		prefixes[i] = p
	}
	ids := make([]interface{}, len(policybundle.BootstrapIdentityAllowSPIFFEIDS))
	for i, id := range policybundle.BootstrapIdentityAllowSPIFFEIDS {
		ids[i] = id
	}
	return map[string]interface{}{
		"neuromesh": map[string]interface{}{
			"desired": map[string]interface{}{
				"deny_path_prefixes":              prefixes,
				"spiffe_ids":                      ids,
				"identity_exception_scope_prefix": policybundle.IdentityExceptionScopePrefix,
			},
		},
	}
}

func storeRootWithExtraPrefix(extra string) map[string]interface{} {
	root := bootstrapStoreRoot()
	desired := root["neuromesh"].(map[string]interface{})["desired"].(map[string]interface{})
	old := desired["deny_path_prefixes"].([]interface{})
	prefixes := append(append([]interface{}(nil), old...), extra)
	desired["deny_path_prefixes"] = prefixes
	return root
}

func TestOPAEvaluator_AllowsBenignPath(t *testing.T) {
	t.Parallel()

	evaluator, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy, bootstrapStoreRoot())
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}

	decision, err := evaluator.Evaluate(context.Background(), PolicyInput{
		BinaryPath: "/usr/bin/bash",
		Identity:   "spiffe://neuromesh.security/untrusted/workload",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow for non-ephemeral path, got deny: %q", decision.DenyReason)
	}
}

func TestOPAEvaluator_DeniesTmpWithoutWhitelist(t *testing.T) {
	t.Parallel()

	evaluator, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy, bootstrapStoreRoot())
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}

	decision, err := evaluator.Evaluate(context.Background(), PolicyInput{
		BinaryPath: "/tmp/evil.bin",
		Identity:   "spiffe://neuromesh.security/untrusted/workload",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny for /tmp execution without whitelisted identity")
	}
	if decision.DenyReason == "" {
		t.Fatal("expected non-empty deny_reason")
	}
}

func TestOPAEvaluator_AllowsTmpForWhitelistedIdentity(t *testing.T) {
	t.Parallel()

	evaluator, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy, bootstrapStoreRoot())
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}

	decision, err := evaluator.Evaluate(context.Background(), PolicyInput{
		BinaryPath: "/tmp/staged-payload",
		Identity:   "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow for whitelisted identity under /tmp/, got deny: %q", decision.DenyReason)
	}
}

func TestOPAEvaluator_DeniesTmpForFlatFormIdentity(t *testing.T) {
	t.Parallel()

	evaluator, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy, bootstrapStoreRoot())
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}

	// Flat shorthand must NOT match path-form whitelist (Slice 2a lock).
	decision, err := evaluator.Evaluate(context.Background(), PolicyInput{
		BinaryPath: "/tmp/staged-payload",
		Identity:   "spiffe://neuromesh.security/agent-ebpf-sensor",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny for flat-form identity after path-form migration")
	}
}

// Regression: /dev/shm/ and /var/tmp/ must be hard-denied for ALL identities,
// including SPIFFE IDs that are whitelisted for the /tmp/-only exception.
// Prior bug: tmp_execution only matched /tmp/, so `allow if { not tmp_execution }`
// incorrectly allowed these prefixes via /v1/evaluate.
func TestOPAEvaluator_HardDeniesDevShmAndVarTmpForAllIdentities(t *testing.T) {
	t.Parallel()

	evaluator, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy, bootstrapStoreRoot())
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}

	whitelisted := "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor"
	untrusted := "spiffe://neuromesh.security/untrusted/workload"

	cases := []struct {
		name       string
		binaryPath string
		identity   string
	}{
		{"dev_shm_untrusted", "/dev/shm/evil.bin", untrusted},
		{"dev_shm_whitelisted", "/dev/shm/evil.bin", whitelisted},
		{"var_tmp_untrusted", "/var/tmp/evil.bin", untrusted},
		{"var_tmp_whitelisted", "/var/tmp/evil.bin", whitelisted},
		{"dev_shm_nested_whitelisted", "/dev/shm/nested/payload", whitelisted},
		{"var_tmp_nested_whitelisted", "/var/tmp/nested/payload", whitelisted},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			decision, err := evaluator.Evaluate(context.Background(), PolicyInput{
				BinaryPath: tc.binaryPath,
				Identity:   tc.identity,
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if decision.Allowed {
				t.Fatalf("expected allowed=false for %s identity=%s (hard-deny ephemeral prefix)",
					tc.binaryPath, tc.identity)
			}
			if decision.DenyReason == "" {
				t.Fatal("expected non-empty deny_reason")
			}
		})
	}
}
