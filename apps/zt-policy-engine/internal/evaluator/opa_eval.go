package evaluator

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
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
	mu     sync.RWMutex
	policy string
	query  rego.PreparedEvalQuery
}

// NewOPAEvaluator compiles and prepares a Rego module with the supplied store
// document (data.neuromesh.desired). storeRoot is typically
// desiredpolicy.RegoDataFromActive().StoreDocument().
func NewOPAEvaluator(ctx context.Context, policy string, storeRoot map[string]interface{}) (*OPAEvaluator, error) {
	if policy == "" {
		policy = DefaultExecutionPolicy
	}
	query, err := prepareEvalQuery(ctx, policy, storeRoot)
	if err != nil {
		return nil, err
	}
	return &OPAEvaluator{policy: policy, query: query}, nil
}

func prepareEvalQuery(ctx context.Context, policy string, storeRoot map[string]interface{}) (rego.PreparedEvalQuery, error) {
	store := inmem.NewFromObject(storeRoot)
	query, err := rego.New(
		rego.Query("data.neuromesh.execution"),
		rego.Module("execution.rego", policy),
		rego.Store(store),
	).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("prepare OPA query: %w", err)
	}
	return query, nil
}

// Reload re-PrepareForEval with a new DesiredPolicy store document. On failure
// the last-good prepared query is retained (fail-closed, never fail-open).
func (e *OPAEvaluator) Reload(ctx context.Context, storeRoot map[string]interface{}) error {
	query, err := prepareEvalQuery(ctx, e.policy, storeRoot)
	if err != nil {
		log.Printf(
			"desired_policy_rego_reload_failed reason=%q action=retain_last_known_good",
			err.Error(),
		)
		return err
	}
	e.mu.Lock()
	e.query = query
	e.mu.Unlock()
	log.Printf("desired_policy_rego_reload_ok")
	return nil
}

// Evaluate runs the prepared policy against the supplied input document.
func (e *OPAEvaluator) Evaluate(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	e.mu.RLock()
	query := e.query
	e.mu.RUnlock()

	results, err := query.Eval(ctx, rego.EvalInput(input))
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
