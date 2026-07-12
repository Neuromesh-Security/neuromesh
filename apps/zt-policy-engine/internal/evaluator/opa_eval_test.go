package evaluator

import (
	"context"
	"testing"
)

func TestOPAEvaluator_AllowsBenignPath(t *testing.T) {
	t.Parallel()

	evaluator, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy)
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
		t.Fatalf("expected allow for non-/tmp path, got deny: %q", decision.DenyReason)
	}
}

func TestOPAEvaluator_DeniesTmpWithoutWhitelist(t *testing.T) {
	t.Parallel()

	evaluator, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy)
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

	evaluator, err := NewOPAEvaluator(context.Background(), DefaultExecutionPolicy)
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}

	decision, err := evaluator.Evaluate(context.Background(), PolicyInput{
		BinaryPath: "/tmp/staged-payload",
		Identity:   "spiffe://neuromesh.security/agent-ebpf-sensor",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow for whitelisted identity, got deny: %q", decision.DenyReason)
	}
}
