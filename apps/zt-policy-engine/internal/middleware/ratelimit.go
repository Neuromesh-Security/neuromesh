// Package middleware provides HTTP middleware for zt-policy-engine.
//
// AggregateRateLimit is a COARSE circuit-breaker for GET /v1/policy-bundle only
// (Issue #176). It is intentionally NOT per-client: every agent shares one
// bearer token (Issue #55 residual), so client identity granularity does not
// exist. Admission webhook rate limiting is explicitly out of scope.
package middleware

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// EnvPolicyBundleRateLimitRPS overrides the default aggregate RPS for
// GET /v1/policy-bundle. Set to 0 to disable (lab only).
const EnvPolicyBundleRateLimitRPS = "NEUROMESH_POLICY_BUNDLE_RATE_LIMIT_RPS"

// DefaultPolicyBundleRPS is the default aggregate request budget for
// GET /v1/policy-bundle.
//
// Reasoning (same discipline as docs/performance-baseline.md EPS claims):
//
//   - POLICY_SYNC_INTERVAL on the agent is 30s (path_deny.POLICY_SYNC_INTERVAL).
//   - Legitimate steady-state load = N_agents / 30 requests per second.
//   - Kubernetes large-cluster design envelope is up to ~5000 nodes
//     (upstream "Considerations for large clusters"); Neuromesh agents are a
//     DaemonSet → at most ~one agent per node → N ≤ 5000.
//   - Steady state at that ceiling: 5000/30 ≈ 166.7 RPS.
//   - Headroom for post-outage sync bunching / clock skew / brief retry storms:
//     ~6× → round to 1000 RPS. Comfortably above legitimate aggregate; still
//     bounds a compromised shared-token holder hammering PE (each response is
//     Cosign-signed).
const DefaultPolicyBundleRPS = 1000

// DefaultRetryAfterSeconds is sent with HTTP 429 when the bucket is empty.
const DefaultRetryAfterSeconds = 1

// AggregateLimiter is a process-wide token bucket (not per-client).
type AggregateLimiter struct {
	mu         sync.Mutex
	ratePerSec float64
	burst      float64
	tokens     float64
	last       time.Time
	retryAfter time.Duration
}

// NewAggregateLimiter builds a limiter with the given sustained RPS.
// Burst equals one second of budget (ratePerSec) so a single synchronized
// fleet tick can land without false 429s under the design envelope.
func NewAggregateLimiter(ratePerSec float64) *AggregateLimiter {
	if ratePerSec < 0 {
		ratePerSec = 0
	}
	burst := ratePerSec
	if burst < 1 && ratePerSec > 0 {
		burst = 1
	}
	return &AggregateLimiter{
		ratePerSec: ratePerSec,
		burst:      burst,
		tokens:     burst,
		last:       time.Now(),
		retryAfter: time.Duration(DefaultRetryAfterSeconds) * time.Second,
	}
}

// NewPolicyBundleLimiterFromEnv reads NEUROMESH_POLICY_BUNDLE_RATE_LIMIT_RPS
// (default DefaultPolicyBundleRPS). Invalid values fall back to the default.
func NewPolicyBundleLimiterFromEnv() *AggregateLimiter {
	raw := os.Getenv(EnvPolicyBundleRateLimitRPS)
	if raw == "" {
		return NewAggregateLimiter(float64(DefaultPolicyBundleRPS))
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || n < 0 {
		log.Printf(
			"invalid %s=%q — using default %d RPS",
			EnvPolicyBundleRateLimitRPS, raw, DefaultPolicyBundleRPS,
		)
		return NewAggregateLimiter(float64(DefaultPolicyBundleRPS))
	}
	if n == 0 {
		log.Printf("%s=0 — policy-bundle aggregate rate limit DISABLED", EnvPolicyBundleRateLimitRPS)
	}
	return NewAggregateLimiter(n)
}

// Allow reports whether one request may proceed and updates the bucket.
func (l *AggregateLimiter) Allow() bool {
	if l == nil || l.ratePerSec == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * l.ratePerSec
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// RetryAfterSeconds returns the Retry-After value for 429 responses.
func (l *AggregateLimiter) RetryAfterSeconds() int {
	if l == nil || l.retryAfter <= 0 {
		return DefaultRetryAfterSeconds
	}
	sec := int(l.retryAfter.Seconds())
	if sec < 1 {
		return 1
	}
	return sec
}

// AggregateRateLimit wraps next with a coarse aggregate limiter.
// On deny: HTTP 429 + Retry-After, empty body (never a signed bundle).
func AggregateRateLimit(limiter *AggregateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter != nil && !limiter.Allow() {
			w.Header().Set("Retry-After", strconv.Itoa(limiter.RetryAfterSeconds()))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
