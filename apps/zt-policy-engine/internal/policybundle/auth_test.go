package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestTokenFingerprintTruncatedSHA256Hex(t *testing.T) {
	token := "super-secret-policy-bundle-token-value"
	fp := TokenFingerprint(token)
	if len(fp) != TokenFingerprintHexLen {
		t.Fatalf("fingerprint len: got %d want %d", len(fp), TokenFingerprintHexLen)
	}
	sum := sha256.Sum256([]byte(token))
	want := hex.EncodeToString(sum[:TokenFingerprintHexLen/2])
	if fp != want {
		t.Fatalf("fingerprint: got %q want %q", fp, want)
	}
	if strings.Contains(fp, token) {
		t.Fatal("fingerprint must not contain raw token")
	}
	if fp == token {
		t.Fatal("fingerprint must not equal raw token")
	}
	// One-way check: fingerprint is not a reversible encoding of the token.
	if _, err := hex.DecodeString(fp); err != nil {
		t.Fatalf("fingerprint must be hex: %v", err)
	}
	decoded, _ := hex.DecodeString(fp)
	if string(decoded) == token || strings.Contains(token, string(decoded)) {
		t.Fatal("truncated digest must not recover token material")
	}
}

func TestMatchBearerTokenDualAccept(t *testing.T) {
	const n = "token-generation-N"
	const n1 = "token-generation-N-plus-1"
	accepted := []string{n, n1}

	fpN, ok := matchBearerToken(n, accepted)
	if !ok || fpN != TokenFingerprint(n) {
		t.Fatalf("N must authenticate: ok=%v fp=%q", ok, fpN)
	}
	fpN1, ok := matchBearerToken(n1, accepted)
	if !ok || fpN1 != TokenFingerprint(n1) {
		t.Fatalf("N+1 must authenticate: ok=%v fp=%q", ok, fpN1)
	}
	if fpN == fpN1 {
		t.Fatal("distinct tokens must have distinct fingerprints")
	}

	// After "retiring" N from the accepted set, N alone is rejected; N+1 still works.
	onlyN1 := []string{n1}
	if _, ok := matchBearerToken(n, onlyN1); ok {
		t.Fatal("retired N must not authenticate against N+1-only set")
	}
	if _, ok := matchBearerToken(n1, onlyN1); !ok {
		t.Fatal("N+1 must still authenticate after N retired")
	}
	if _, ok := matchBearerToken("wrong", accepted); ok {
		t.Fatal("wrong token must not authenticate")
	}
}

func TestMatchBearerTokenAlwaysComparesAllCandidates(t *testing.T) {
	// Structural timing-safety: match must succeed for the *last* candidate
	// without depending on early-exit short-circuit (which would leak index).
	// We cannot assert nanosecond equality in CI; we assert behavioral parity
	// for first vs last match and that invalid still rejects after full scan.
	accepted := []string{
		"alpha-token-aaaaaaaa",
		"bravo-token-bbbbbbbb",
		"charlie-token-cccccc",
	}
	fpFirst, okFirst := matchBearerToken(accepted[0], accepted)
	fpLast, okLast := matchBearerToken(accepted[2], accepted)
	if !okFirst || !okLast {
		t.Fatalf("first/last must both match: %v %v", okFirst, okLast)
	}
	if fpFirst != TokenFingerprint(accepted[0]) || fpLast != TokenFingerprint(accepted[2]) {
		t.Fatalf("fingerprints: first=%q last=%q", fpFirst, fpLast)
	}
	if _, ok := matchBearerToken("nope", accepted); ok {
		t.Fatal("invalid must fail after comparing all candidates")
	}
}

func TestAuthorizeBearerRecordsFingerprintNotRawToken(t *testing.T) {
	const n = "metric-test-token-N"
	const n1 = "metric-test-token-N1"
	fpN := TokenFingerprint(n)
	fpN1 := TokenFingerprint(n1)

	beforeN := testutil.ToFloat64(AuthAcceptCounterForTest().WithLabelValues(fpN))
	beforeN1 := testutil.ToFloat64(AuthAcceptCounterForTest().WithLabelValues(fpN1))

	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+n)
	if !authorizeBearer(req, []string{n, n1}) {
		t.Fatal("expected authorize success for N")
	}
	req2 := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req2.Header.Set("Authorization", "Bearer "+n1)
	if !authorizeBearer(req2, []string{n, n1}) {
		t.Fatal("expected authorize success for N+1")
	}

	afterN := testutil.ToFloat64(AuthAcceptCounterForTest().WithLabelValues(fpN))
	afterN1 := testutil.ToFloat64(AuthAcceptCounterForTest().WithLabelValues(fpN1))
	if afterN != beforeN+1 || afterN1 != beforeN1+1 {
		t.Fatalf("counters: N %v→%v N+1 %v→%v", beforeN, afterN, beforeN1, afterN1)
	}

	// Reject path must not create labels from the presented (attacker) secret.
	bad := "attacker-controlled-bearer"
	badFP := TokenFingerprint(bad)
	beforeBad := testutil.ToFloat64(AuthAcceptCounterForTest().WithLabelValues(badFP))
	req3 := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req3.Header.Set("Authorization", "Bearer "+bad)
	if authorizeBearer(req3, []string{n, n1}) {
		t.Fatal("bad token must not authorize")
	}
	afterBad := testutil.ToFloat64(AuthAcceptCounterForTest().WithLabelValues(badFP))
	if afterBad != beforeBad {
		t.Fatal("reject must not increment accept_total for attacker-presented fingerprint")
	}
}

func TestHandlerDualTokenBothAuthenticate(t *testing.T) {
	const n = "dual-N"
	const n1 = "dual-N1"
	signer := testEd25519Signer(t)
	h := Handler([]string{n, n1}, signer)

	for _, tok := range []string{n, n1} {
		req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("token %q: status %d body=%q", tok, rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer retired-alone")
	rr := httptest.NewRecorder()
	Handler([]string{n1}, signer).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unknown against N+1-only: got %d", rr.Code)
	}

	reqN := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	reqN.Header.Set("Authorization", "Bearer "+n)
	rrN := httptest.NewRecorder()
	Handler([]string{n1}, signer).ServeHTTP(rrN, reqN)
	if rrN.Code != http.StatusUnauthorized {
		t.Fatalf("retired N against N+1-only: got %d want 401", rrN.Code)
	}
}

func TestLoadTokensFromEnvMultilineAndPreviousSibling(t *testing.T) {
	dir := t.TempDir()
	accepted := filepath.Join(dir, "accepted")
	prev := filepath.Join(dir, "token-previous")
	if err := os.WriteFile(accepted, []byte("tok-A\ntok-B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prev, []byte("tok-C\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(accepted)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvPolicyBundleTokenFile, abs)
	t.Setenv(EnvPolicyBundleTokenPreviousFile, "")
	t.Setenv(EnvPolicyBundleToken, "")
	got, err := LoadTokensFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 tokens (A,B + sibling C), got %#v", got)
	}
	want := map[string]bool{"tok-A": true, "tok-B": true, "tok-C": true}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected token %q in %#v", g, got)
		}
	}
}

func TestLoadTokensFromEnvDedupe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("same\nsame\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvPolicyBundleTokenFile, abs)
	t.Setenv(EnvPolicyBundleToken, "")
	got, err := LoadTokensFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "same" {
		t.Fatalf("dedupe: got %#v", got)
	}
}
