package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAggregateLimiterAllowsUnderBudget(t *testing.T) {
	l := NewAggregateLimiter(10)
	for i := 0; i < 10; i++ {
		if !l.Allow() {
			t.Fatalf("request %d unexpectedly denied", i)
		}
	}
}

func TestAggregateLimiterDeniesWhenExhausted(t *testing.T) {
	l := NewAggregateLimiter(5)
	for i := 0; i < 5; i++ {
		if !l.Allow() {
			t.Fatalf("request %d unexpectedly denied", i)
		}
	}
	if l.Allow() {
		t.Fatal("expected deny after burst exhausted")
	}
}

func TestAggregateLimiterRefillsOverTime(t *testing.T) {
	l := NewAggregateLimiter(100)
	for i := 0; i < 100; i++ {
		if !l.Allow() {
			t.Fatalf("warmup %d denied", i)
		}
	}
	if l.Allow() {
		t.Fatal("expected empty bucket")
	}
	// Advance virtual time by mutating last (unit-test seam).
	l.mu.Lock()
	l.last = time.Now().Add(-50 * time.Millisecond)
	l.mu.Unlock()
	if !l.Allow() {
		t.Fatal("expected refill after 50ms at 100 RPS (~5 tokens)")
	}
}

func TestAggregateLimiterZeroDisables(t *testing.T) {
	l := NewAggregateLimiter(0)
	for i := 0; i < 1000; i++ {
		if !l.Allow() {
			t.Fatalf("disabled limiter denied request %d", i)
		}
	}
}

func TestAggregateRateLimitReturns429AndRetryAfter(t *testing.T) {
	l := NewAggregateLimiter(1)
	var hits atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := AggregateRateLimit(l, next)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("first request: got %d", rr.Code)
	}

	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil))
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d want 429", rr2.Code)
	}
	if rr2.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After: got %q want 1", rr2.Header().Get("Retry-After"))
	}
	if hits.Load() != 1 {
		t.Fatalf("next called %d times want 1", hits.Load())
	}
}

func TestAggregateRateLimitIsCoarseNotPerClient(t *testing.T) {
	// Two "clients" share one limiter — exhausting budget from A blocks B.
	l := NewAggregateLimiter(2)
	h := AggregateRateLimit(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
		req.Header.Set("Authorization", "Bearer client-A")
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("client-A req %d: %d", i, rr.Code)
		}
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/policy-bundle", nil)
	req.Header.Set("Authorization", "Bearer client-B")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("client-B should be blocked by shared aggregate budget, got %d", rr.Code)
	}
}

func TestAggregateLimiterConcurrentDoesNotExceedBurstPlusRace(t *testing.T) {
	l := NewAggregateLimiter(50)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow() {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	got := allowed.Load()
	if got > 50 {
		t.Fatalf("allowed %d > burst 50", got)
	}
	if got < 1 {
		t.Fatal("expected some allows")
	}
}

func TestDefaultPolicyBundleRPSHeadroomMath(t *testing.T) {
	// Lock the documented envelope so a drive-by constant change fails CI.
	const (
		k8sLargeClusterNodes = 5000
		syncIntervalSecs     = 30
		minHeadroomFactor    = 5.0
	)
	steadyStateRPS := float64(k8sLargeClusterNodes) / float64(syncIntervalSecs) // ≈166.67
	minAllowed := int(steadyStateRPS * minHeadroomFactor)
	if DefaultPolicyBundleRPS < minAllowed {
		t.Fatalf(
			"DefaultPolicyBundleRPS=%d too low for %d agents / %ds (need ≥%d with %.0f× headroom)",
			DefaultPolicyBundleRPS, k8sLargeClusterNodes, syncIntervalSecs,
			minAllowed, minHeadroomFactor,
		)
	}
}
