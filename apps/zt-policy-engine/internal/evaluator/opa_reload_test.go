package evaluator

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
)

func TestOPAEvaluator_ReloadFailureRetainsLastGood(t *testing.T) {
	opa, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy, bootstrapStoreRoot())
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}

	stagingPath := "/opt/staging/payload"
	before, err := opa.Evaluate(context.Background(), PolicyInput{
		BinaryPath: stagingPath,
		Identity:   "spiffe://neuromesh.security/untrusted/workload",
	})
	if err != nil {
		t.Fatalf("Evaluate before reload: %v", err)
	}
	if !before.Allowed {
		t.Fatalf("bootstrap should allow %s, got deny: %q", stagingPath, before.DenyReason)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Corrupt module source so PrepareForEval fails; Reload retains last-good query.
	opa.policy = "package broken\nthis is not valid rego !!!"
	if err := opa.Reload(context.Background(), storeRootWithExtraPrefix("/opt/staging/")); err == nil {
		t.Fatal("expected reload failure with invalid policy module")
	}
	out := buf.String()
	if !strings.Contains(out, "desired_policy_rego_reload_failed") {
		t.Fatalf("expected reload failure log, got:\n%s", out)
	}
	if !strings.Contains(out, "retain_last_known_good") {
		t.Fatalf("expected retain_last_known_good in log, got:\n%s", out)
	}

	after, err := opa.Evaluate(context.Background(), PolicyInput{
		BinaryPath: stagingPath,
		Identity:   "spiffe://neuromesh.security/untrusted/workload",
	})
	if err != nil {
		t.Fatalf("Evaluate after failed reload: %v", err)
	}
	if after.Allowed != before.Allowed {
		t.Fatalf("decision changed after failed reload: before=%v after=%v", before.Allowed, after.Allowed)
	}
}

func TestOPAEvaluator_ReloadUpdatesDecision(t *testing.T) {
	opa, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy, bootstrapStoreRoot())
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}

	stagingPath := "/opt/staging/payload"
	before, err := opa.Evaluate(context.Background(), PolicyInput{
		BinaryPath: stagingPath,
		Identity:   "spiffe://neuromesh.security/untrusted/workload",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !before.Allowed {
		t.Fatal("expected allow before reload")
	}

	if err := opa.Reload(context.Background(), storeRootWithExtraPrefix("/opt/staging/")); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	after, err := opa.Evaluate(context.Background(), PolicyInput{
		BinaryPath: stagingPath,
		Identity:   "spiffe://neuromesh.security/untrusted/workload",
	})
	if err != nil {
		t.Fatalf("Evaluate after reload: %v", err)
	}
	if after.Allowed {
		t.Fatal("expected deny after reload added /opt/staging/ prefix")
	}
}
