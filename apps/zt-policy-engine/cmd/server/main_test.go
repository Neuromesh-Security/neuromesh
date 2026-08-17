package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"neuromesh/zt-policy-engine/internal/desiredpolicy"
	"neuromesh/zt-policy-engine/internal/evaluator"
	"neuromesh/zt-policy-engine/internal/identity"
	"neuromesh/zt-policy-engine/internal/policybundle"
)

// TestDesiredPolicyMutationMovesBundleAndRegoPlanes is the Issue #137 PR-2 proof:
// one ApplyValidated mutation must move BOTH GET /v1/policy-bundle content and
// POST /v1/evaluate outcomes together (closes bundle/Rego drift risk).
func TestDesiredPolicyMutationMovesBundleAndRegoPlanes(t *testing.T) {
	t.Cleanup(func() {
		desiredpolicy.ClearForTest()
		desiredpolicy.ClearRegoReloaderForTest()
	})

	ctx := context.Background()
	initialRego := desiredpolicy.RegoDataFromActive()
	opa, err := evaluator.NewOPAEvaluator(ctx, evaluator.DefaultExecutionPolicy, initialRego.StoreDocument())
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}
	desiredpolicy.SetRegoReloader(&opaRegoReloader{opa: opa})

	spiffe, err := identity.NewSPIFFEValidator(ctx, identity.ValidatorConfig{
		TrustDomain:          "neuromesh.security",
		InsecureMockIdentity: true,
	})
	if err != nil {
		t.Fatalf("NewSPIFFEValidator: %v", err)
	}
	defer func() { _ = spiffe.Close() }()

	const token = "test-bundle-token"
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := policybundle.ParsePKCS8Signer(mustPKCS8PEM(t, priv))
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/policy-bundle", policybundle.Handler(token, signer))
	mux.HandleFunc("POST /v1/evaluate", evaluateHandler(opa, spiffe))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	stagingPath := "/opt/staging/payload"

	if !evaluateAllowed(t, srv.URL, stagingPath) {
		t.Fatal("bootstrap rego should allow path outside deny prefixes")
	}
	if n := len(fetchBundleDenyPrefixes(t, srv.URL, token)); n != 3 {
		t.Fatalf("bootstrap bundle deny prefixes: want 3 got %d", n)
	}

	snap, err := desiredpolicy.Validate(desiredpolicy.Document{
		DenyPathPrefixes: append(append([]string(nil), desiredpolicy.FloorDenyPathPrefixes...), "/opt/staging/"),
		IdentityAllowExceptions: &desiredpolicy.IdentityAllowExceptions{
			ScopePathPrefix: desiredpolicy.DefaultIdentityExceptionScopePrefix,
			SpiffeIDs:       append([]string(nil), policybundle.BootstrapIdentityAllowSPIFFEIDS...),
		},
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := desiredpolicy.ApplyValidated(snap); err != nil {
		t.Fatalf("ApplyValidated: %v", err)
	}

	prefixes := fetchBundleDenyPrefixes(t, srv.URL, token)
	if len(prefixes) != 4 {
		t.Fatalf("bundle deny prefixes after mutation: want 4 got %v", prefixes)
	}
	found := false
	for _, p := range prefixes {
		if p == "/opt/staging/" {
			found = true
		}
	}
	if !found {
		t.Fatalf("bundle missing /opt/staging/: %v", prefixes)
	}

	if evaluateAllowed(t, srv.URL, stagingPath) {
		t.Fatal("rego should deny path under newly added /opt/staging/ prefix")
	}
}

func evaluateAllowed(t *testing.T, baseURL, binaryPath string) bool {
	t.Helper()
	body, err := json.Marshal(map[string]string{"binary_path": binaryPath})
	if err != nil {
		t.Fatalf("marshal evaluate request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/evaluate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluate status %d", resp.StatusCode)
	}
	var out evaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode evaluate response: %v", err)
	}
	return out.Allowed
}

func fetchBundleDenyPrefixes(t *testing.T, baseURL, token string) []string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/policy-bundle", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/policy-bundle: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("policy-bundle status %d", resp.StatusCode)
	}
	var bundle policybundle.Bundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	return bundle.DenyPathPrefixes
}

func mustPKCS8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
