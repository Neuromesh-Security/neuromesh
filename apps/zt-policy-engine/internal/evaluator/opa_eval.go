package evaluator

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed policies/execution.rego
var DefaultExecutionPolicy string

// PolicyInput is the Rego input document for execution authorization.
type PolicyInput struct {
	BinaryPath string `json:"binary_path"`
	Identity   string `json:"identity"`
	PID        uint32 `json:"pid,omitempty"`
	PPID       uint32 `json:"ppid,omitempty"`
}

// PolicyDecision is the normalized outcome of an OPA evaluation.
type PolicyDecision struct {
	Allowed    bool   `json:"allowed"`
	DenyReason string `json:"deny_reason,omitempty"`
}

// OPAEvaluator evaluates Rego policies in-memory using a prepared query cache.
type OPAEvaluator struct {
	query rego.PreparedEvalQuery
}

// NewOPAEvaluator compiles and prepares a Rego module for repeated low-latency evaluation.
func NewOPAEvaluator(ctx context.Context, policy string) (*OPAEvaluator, error) {
	if policy == "" {
		policy = DefaultExecutionPolicy
	}

	query, err := rego.New(
		rego.Query("data.neuromesh.execution"),
		rego.Module("execution.rego", policy),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare OPA query: %w", err)
	}

	return &OPAEvaluator{query: query}, nil
}

// Evaluate runs the prepared policy against the supplied input document.
func (e *OPAEvaluator) Evaluate(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return PolicyDecision{}, fmt.Errorf("evaluate policy: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return PolicyDecision{Allowed: false, DenyReason: "policy returned no decision"}, nil
	}

	value, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return PolicyDecision{}, fmt.Errorf("unexpected policy result type %T", results[0].Expressions[0].Value)
	}

	allowed, _ := value["allow"].(bool)
	denyReason, _ := value["deny_reason"].(string)

	return PolicyDecision{
		Allowed:    allowed,
		DenyReason: denyReason,
	}, nil
}
