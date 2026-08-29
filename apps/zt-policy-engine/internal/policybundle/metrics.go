package policybundle

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// policy_bundle_auth_accept_total{fp="<truncated-sha256-hex>"} — Issue #179.
// Label values are TokenFingerprint output only (never raw tokens).
var authAcceptTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "policy_bundle_auth_accept_total",
		Help: "Successful GET /v1/policy-bundle bearer authentications by opaque token fingerprint (truncated SHA-256 hex; never the raw token).",
	},
	[]string{"fp"},
)

// RecordAuthAccept increments the accept counter for an opaque fingerprint.
// fp must already be TokenFingerprint output — callers must not pass raw tokens.
func RecordAuthAccept(fp string) {
	if fp == "" || len(fp) != TokenFingerprintHexLen {
		return
	}
	authAcceptTotal.WithLabelValues(fp).Inc()
}

// AuthAcceptCounterForTest exposes the counter vec for unit tests.
func AuthAcceptCounterForTest() *prometheus.CounterVec {
	return authAcceptTotal
}
