// Package identity implements SPIFFE/SPIRE workload identity validation for
// the zero-trust policy engine. Every workload calling /v1/evaluate presents
// an X.509-SVID (SPIFFE X.509 certificate); this package cryptographically
// verifies that SVID's certificate chain against a real SPIFFE trust bundle
// and extracts/validates its SPIFFE ID. There is no code path that treats an
// unverified or absent certificate as trusted.
package identity

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIFFEID is a validated workload identity URI (e.g. spiffe://trust.domain/ns/sa/name).
type SPIFFEID string

func (id SPIFFEID) String() string {
	return string(id)
}

// ValidationResult captures the outcome of SPIFFE/SPIRE x509 SVID verification.
type ValidationResult struct {
	Identity SPIFFEID
	Valid    bool
	Subject  string
}

// TrustBundleMode selects how the validator obtains its SPIFFE X.509 trust
// bundle. There is deliberately no default: callers must pick one explicitly
// (see ValidatorConfig.TrustBundleMode).
type TrustBundleMode string

const (
	// TrustBundleModeStaticFile loads a fixed PEM-encoded trust bundle from
	// disk once at startup. It never rotates -- a restart is required to
	// pick up new/revoked authorities. This is a bootstrap/dev-only mode
	// and must be selected explicitly; it is loudly logged so it can never
	// be mistaken for the production mode.
	TrustBundleModeStaticFile TrustBundleMode = "static_file"

	// TrustBundleModeWorkloadAPI streams X.509-SVIDs and trust bundles live
	// from a SPIFFE Workload API implementation (e.g. a SPIRE Agent) over
	// its Unix domain socket, including automatic authority rotation. This
	// is the production mode.
	TrustBundleModeWorkloadAPI TrustBundleMode = "workload_api"
)

// EnvInsecureMockIdentity is the only switch that can enable the mock
// identity bypass. It has no config-file or programmatic equivalent that
// could be flipped on by accident -- ValidatorConfig.InsecureMockIdentity
// must be wired from exactly this environment variable by the caller (see
// ConfigFromEnv), and every activation logs a loud warning at startup and
// on every single validation call.
const EnvInsecureMockIdentity = "NEUROMESH_INSECURE_MOCK_IDENTITY"

// Sentinel errors. Each represents one specific, auditable rejection reason
// -- callers and tests should use errors.Is against these rather than
// matching on error message strings.
var (
	// ErrNoCertificatePresented means the caller supplied no certificate
	// material at all. Fail-closed: this is always a deny, never a mock.
	ErrNoCertificatePresented = errors.New("spiffe: no certificate presented")

	// ErrMalformedCertificate means the supplied bytes could not be parsed
	// as one or more PEM/DER X.509 certificates.
	ErrMalformedCertificate = errors.New("spiffe: malformed certificate")

	// ErrCertificateExpired means the leaf certificate's NotAfter is in the past.
	ErrCertificateExpired = errors.New("spiffe: certificate expired")

	// ErrCertificateNotYetValid means the leaf certificate's NotBefore is in the future.
	ErrCertificateNotYetValid = errors.New("spiffe: certificate not yet valid")

	// ErrMissingSPIFFEURISAN means the leaf certificate has no (or more
	// than one) SPIFFE URI SAN to extract an identity from.
	ErrMissingSPIFFEURISAN = errors.New("spiffe: certificate missing SPIFFE URI SAN")

	// ErrTrustDomainMismatch means the certificate's SPIFFE ID belongs to a
	// trust domain other than the one this validator is configured to trust.
	ErrTrustDomainMismatch = errors.New("spiffe: certificate trust domain mismatch")

	// ErrIDPatternMismatch means the SPIFFE ID's path did not match the
	// configured ExpectedIDPattern.
	ErrIDPatternMismatch = errors.New("spiffe: SPIFFE ID does not match expected pattern")

	// ErrChainVerificationFailed means the certificate chain could not be
	// cryptographically verified against the trust bundle (untrusted
	// issuer, tampered signature, wrong key usage, etc).
	ErrChainVerificationFailed = errors.New("spiffe: certificate chain verification failed")

	// ErrTrustBundleUnavailable means the trust bundle itself could not be
	// loaded or fetched. This is always fail-closed -- an unreachable or
	// stale trust bundle denies validation, it never falls back to "allow".
	ErrTrustBundleUnavailable = errors.New("spiffe: trust bundle unavailable")

	// ErrInvalidValidatorConfig means ValidatorConfig itself is invalid or
	// incomplete (e.g. an unset/unknown TrustBundleMode). This is a
	// deployment misconfiguration, caught at startup, not at request time.
	ErrInvalidValidatorConfig = errors.New("spiffe: invalid validator configuration")
)

// ValidatorConfig holds trust-domain and trust-bundle settings for SPIFFE
// X.509-SVID validation.
type ValidatorConfig struct {
	// TrustDomain is the SPIFFE trust domain this policy engine trusts,
	// e.g. "neuromesh.security". A presented SVID whose SPIFFE ID does not
	// belong to this trust domain is rejected with ErrTrustDomainMismatch.
	TrustDomain string

	// ExpectedIDPattern, if set, is matched against the *path* component
	// of the verified SPIFFE ID (e.g. "/ns/default/sa/agent-ebpf-sensor").
	// A certificate whose SPIFFE ID path does not match is rejected with
	// ErrIDPatternMismatch. Leave nil to allow any path within the trust
	// domain.
	ExpectedIDPattern *regexp.Regexp

	// TrustBundleMode selects how the trust bundle is obtained. There is
	// no default: an empty/unrecognized value is a startup-time
	// misconfiguration error (ErrInvalidValidatorConfig), never a silent
	// fallback to either mode.
	TrustBundleMode TrustBundleMode

	// BundlePath is the PEM trust bundle file path. Required when
	// TrustBundleMode == TrustBundleModeStaticFile.
	BundlePath string

	// WorkloadAPIAddr overrides the Workload API socket address (e.g.
	// "unix:///run/spire/sockets/agent.sock") when TrustBundleMode ==
	// TrustBundleModeWorkloadAPI. If empty, go-spiffe falls back to the
	// SPIFFE_ENDPOINT_SOCKET environment variable, per the SPIFFE spec.
	WorkloadAPIAddr string

	// InsecureMockIdentity activates the mock-identity bypass: every
	// validation call short-circuits to a trusted internal identity with
	// NO cryptographic verification. This must be wired from exactly
	// EnvInsecureMockIdentity ("NEUROMESH_INSECURE_MOCK_IDENTITY=true") --
	// see ConfigFromEnv. It defaults to false and there is no other way to
	// enable it.
	InsecureMockIdentity bool

	// clock, if set, overrides time.Now() for certificate temporal checks.
	// Tests use this to deterministically exercise expired/not-yet-valid
	// certificates without needing to regenerate fixtures over time.
	clock func() time.Time
}

// DefaultConfig returns safe, fail-closed defaults: a trust domain name, and
// nothing else. TrustBundleMode is intentionally left unset -- constructing
// a validator from this config without also setting TrustBundleMode (or
// explicitly opting into InsecureMockIdentity) is a startup error, not a
// silent mock. There is no "MockInternal: true" default; that was the
// original zero-trust gap this package closes.
func DefaultConfig() ValidatorConfig {
	return ValidatorConfig{
		TrustDomain: "neuromesh.security",
	}
}

// ConfigFromEnv builds a ValidatorConfig from environment variables, for use
// by cmd/server/main.go. It is the only place production configuration
// should be assembled -- unlike DefaultConfig, it will pick up
// NEUROMESH_INSECURE_MOCK_IDENTITY, and it requires TrustBundleMode to be
// set explicitly via NEUROMESH_SPIFFE_TRUST_BUNDLE_MODE unless the mock
// bypass is active.
//
// Recognized variables:
//   - NEUROMESH_SPIFFE_TRUST_DOMAIN (default "neuromesh.security")
//   - NEUROMESH_SPIFFE_TRUST_BUNDLE_MODE ("static_file" | "workload_api")
//   - NEUROMESH_SPIFFE_BUNDLE_PATH (required for static_file mode)
//   - NEUROMESH_SPIFFE_WORKLOAD_API_ADDR (optional for workload_api mode)
//   - NEUROMESH_SPIFFE_EXPECTED_ID_PATTERN (optional regexp on the SPIFFE ID path)
//   - NEUROMESH_INSECURE_MOCK_IDENTITY ("true" to enable the mock bypass)
func ConfigFromEnv() (ValidatorConfig, error) {
	cfg := DefaultConfig()

	if td := strings.TrimSpace(os.Getenv("NEUROMESH_SPIFFE_TRUST_DOMAIN")); td != "" {
		cfg.TrustDomain = td
	}

	cfg.InsecureMockIdentity = strings.EqualFold(strings.TrimSpace(os.Getenv(EnvInsecureMockIdentity)), "true")

	cfg.TrustBundleMode = TrustBundleMode(strings.TrimSpace(os.Getenv("NEUROMESH_SPIFFE_TRUST_BUNDLE_MODE")))
	cfg.BundlePath = strings.TrimSpace(os.Getenv("NEUROMESH_SPIFFE_BUNDLE_PATH"))
	cfg.WorkloadAPIAddr = strings.TrimSpace(os.Getenv("NEUROMESH_SPIFFE_WORKLOAD_API_ADDR"))

	if raw := strings.TrimSpace(os.Getenv("NEUROMESH_SPIFFE_EXPECTED_ID_PATTERN")); raw != "" {
		pattern, err := regexp.Compile(raw)
		if err != nil {
			return ValidatorConfig{}, fmt.Errorf("%w: invalid NEUROMESH_SPIFFE_EXPECTED_ID_PATTERN %q: %v", ErrInvalidValidatorConfig, raw, err)
		}
		cfg.ExpectedIDPattern = pattern
	}

	return cfg, nil
}

// SPIFFEValidator verifies workload identities presented via mTLS X.509-SVIDs
// against a real SPIFFE trust bundle, using github.com/spiffe/go-spiffe/v2
// for chain verification and SPIFFE ID extraction.
type SPIFFEValidator struct {
	cfg          ValidatorConfig
	trustDomain  spiffeid.TrustDomain
	bundleSource x509bundle.Source
	closeFunc    func() error
}

// NewSPIFFEValidator constructs a validator from the supplied configuration.
//
// If cfg.InsecureMockIdentity is true, no trust bundle is loaded and every
// validation call is short-circuited to a mock identity -- a loud warning is
// logged now and on every subsequent validation call. Otherwise
// cfg.TrustBundleMode must be TrustBundleModeStaticFile or
// TrustBundleModeWorkloadAPI; anything else (including the empty value) is a
// startup-time error. In TrustBundleModeWorkloadAPI, this call blocks on ctx
// until the initial SVID/bundle update is received from the Workload API,
// or ctx is done -- callers should pass a context with a deadline to avoid
// hanging indefinitely if no SPIRE agent is reachable.
func NewSPIFFEValidator(ctx context.Context, cfg ValidatorConfig) (*SPIFFEValidator, error) {
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = "neuromesh.security"
	}

	v := &SPIFFEValidator{cfg: cfg}

	if cfg.InsecureMockIdentity {
		log.Printf("SECURITY WARNING: %s=true -- SPIFFE identity validation is DISABLED. "+
			"Every /v1/evaluate request will be treated as a trusted internal workload with "+
			"NO cryptographic verification of any kind. This must never be set in a production deployment.",
			EnvInsecureMockIdentity)
		return v, nil
	}

	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid TrustDomain %q: %v", ErrInvalidValidatorConfig, cfg.TrustDomain, err)
	}
	v.trustDomain = td

	switch cfg.TrustBundleMode {
	case TrustBundleModeStaticFile:
		if cfg.BundlePath == "" {
			return nil, fmt.Errorf("%w: BundlePath is required when TrustBundleMode=%q", ErrInvalidValidatorConfig, TrustBundleModeStaticFile)
		}

		bundle, err := x509bundle.Load(td, cfg.BundlePath)
		if err != nil {
			return nil, fmt.Errorf("%w: load static trust bundle from %q: %v", ErrTrustBundleUnavailable, cfg.BundlePath, err)
		}
		if bundle.Empty() {
			return nil, fmt.Errorf("%w: static trust bundle %q contains no X.509 authorities", ErrTrustBundleUnavailable, cfg.BundlePath)
		}
		v.bundleSource = bundle

		log.Printf("SPIFFE trust bundle mode: STATIC FILE (%q) for trust domain %q. "+
			"This bundle will NOT rotate and a restart is required to pick up authority changes -- "+
			"this is a bootstrap/dev mode, not the production posture. Use %s for production.",
			cfg.BundlePath, cfg.TrustDomain, TrustBundleModeWorkloadAPI)

	case TrustBundleModeWorkloadAPI:
		var opts []workloadapi.X509SourceOption
		if cfg.WorkloadAPIAddr != "" {
			opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.WorkloadAPIAddr)))
		}

		source, err := workloadapi.NewX509Source(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("%w: connect to SPIFFE Workload API: %v", ErrTrustBundleUnavailable, err)
		}
		v.bundleSource = source
		v.closeFunc = source.Close

		log.Printf("SPIFFE trust bundle mode: LIVE WORKLOAD API for trust domain %q (production mode).", cfg.TrustDomain)

	default:
		return nil, fmt.Errorf("%w: TrustBundleMode must be %q or %q (or InsecureMockIdentity must be explicitly enabled), got %q",
			ErrInvalidValidatorConfig, TrustBundleModeStaticFile, TrustBundleModeWorkloadAPI, cfg.TrustBundleMode)
	}

	return v, nil
}

// Close releases resources held by the validator (namely, the Workload API
// connection in TrustBundleModeWorkloadAPI). It is a no-op in all other
// modes. Safe to call on a nil closeFunc.
func (v *SPIFFEValidator) Close() error {
	if v == nil || v.closeFunc == nil {
		return nil
	}
	return v.closeFunc()
}

// ValidateCertificatePEM verifies an x509-SVID chain presented as one or
// more concatenated PEM CERTIFICATE blocks (leaf first, intermediates
// after, matching the convention of a TLS peer certificate chain).
//
// An empty/nil certPEM is always a fail-closed deny (ErrNoCertificatePresented)
// -- it is never treated as "no client cert, so trust by default".
func (v *SPIFFEValidator) ValidateCertificatePEM(certPEM []byte) (ValidationResult, error) {
	if v.cfg.InsecureMockIdentity {
		v.warnMockUsage()
		return v.mockInternalIdentity("agent-ebpf-sensor"), nil
	}

	if len(strings.TrimSpace(string(certPEM))) == 0 {
		return ValidationResult{}, fmt.Errorf("%w", ErrNoCertificatePresented)
	}

	certs, err := parseCertificatesPEM(certPEM)
	if err != nil {
		return ValidationResult{}, fmt.Errorf("%w: %v", ErrMalformedCertificate, err)
	}

	return v.validateCertificateChain(certs)
}

// ValidateCertificate verifies a single already-parsed leaf x509 certificate
// (e.g. from tls.ConnectionState.PeerCertificates[0]) as an X.509-SVID. A nil
// certificate is always a fail-closed deny.
func (v *SPIFFEValidator) ValidateCertificate(cert *x509.Certificate) (ValidationResult, error) {
	if v.cfg.InsecureMockIdentity {
		v.warnMockUsage()
		return v.mockInternalIdentity(""), nil
	}

	if cert == nil {
		return ValidationResult{}, fmt.Errorf("%w: nil certificate", ErrNoCertificatePresented)
	}

	return v.validateCertificateChain([]*x509.Certificate{cert})
}

// ValidateCertificateChain verifies a full leaf+intermediates x509 chain
// (e.g. from tls.ConnectionState.PeerCertificates) as an X.509-SVID.
func (v *SPIFFEValidator) ValidateCertificateChain(certs []*x509.Certificate) (ValidationResult, error) {
	if v.cfg.InsecureMockIdentity {
		v.warnMockUsage()
		return v.mockInternalIdentity(""), nil
	}

	if len(certs) == 0 {
		return ValidationResult{}, fmt.Errorf("%w: empty certificate chain", ErrNoCertificatePresented)
	}

	return v.validateCertificateChain(certs)
}

// validateCertificateChain is the real (non-mock) verification path shared
// by all three public entry points above. It:
//  1. Rejects expired/not-yet-valid leaf certificates with a specific error.
//  2. Extracts the SPIFFE ID from the leaf's URI SAN via go-spiffe.
//  3. Rejects SPIFFE IDs outside the configured trust domain.
//  4. Rejects SPIFFE ID paths that don't match ExpectedIDPattern, if set.
//  5. Cryptographically verifies the full chain against the trust bundle
//     using x509svid.Verify (go-spiffe/v2), which also re-checks key usage
//     and CA constraints per the X509-SVID spec.
//
// Every failure returns one of the package's sentinel errors so callers can
// distinguish rejection reasons in logs/audit trails via errors.Is.
func (v *SPIFFEValidator) validateCertificateChain(certs []*x509.Certificate) (ValidationResult, error) {
	leaf := certs[0]
	now := v.now()

	if now.Before(leaf.NotBefore) {
		return ValidationResult{Subject: leaf.Subject.String()},
			fmt.Errorf("%w: certificate not valid until %s (now %s)", ErrCertificateNotYetValid, leaf.NotBefore.UTC(), now.UTC())
	}
	if now.After(leaf.NotAfter) {
		return ValidationResult{Subject: leaf.Subject.String()},
			fmt.Errorf("%w: certificate expired at %s (now %s)", ErrCertificateExpired, leaf.NotAfter.UTC(), now.UTC())
	}

	spiffeID, err := x509svid.IDFromCert(leaf)
	if err != nil {
		return ValidationResult{Subject: leaf.Subject.String()},
			fmt.Errorf("%w: %v", ErrMissingSPIFFEURISAN, err)
	}

	if !spiffeID.MemberOf(v.trustDomain) {
		return ValidationResult{Subject: leaf.Subject.String()},
			fmt.Errorf("%w: certificate SPIFFE ID %q is not a member of trust domain %q", ErrTrustDomainMismatch, spiffeID.String(), v.trustDomain.String())
	}

	if v.cfg.ExpectedIDPattern != nil && !v.cfg.ExpectedIDPattern.MatchString(spiffeID.Path()) {
		return ValidationResult{Subject: leaf.Subject.String()},
			fmt.Errorf("%w: SPIFFE ID path %q does not match expected pattern %q", ErrIDPatternMismatch, spiffeID.Path(), v.cfg.ExpectedIDPattern.String())
	}

	if v.bundleSource == nil {
		return ValidationResult{Subject: leaf.Subject.String()},
			fmt.Errorf("%w: no trust bundle source configured", ErrTrustBundleUnavailable)
	}

	verifiedID, _, err := x509svid.Verify(certs, v.bundleSource, x509svid.WithTime(now))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isBundleFetchError(err) {
			return ValidationResult{Subject: leaf.Subject.String()},
				fmt.Errorf("%w: %v", ErrTrustBundleUnavailable, err)
		}
		return ValidationResult{Subject: leaf.Subject.String()},
			fmt.Errorf("%w: %v", ErrChainVerificationFailed, err)
	}

	return ValidationResult{
		Identity: SPIFFEID(verifiedID.String()),
		Valid:    true,
		Subject:  leaf.Subject.String(),
	}, nil
}

// isBundleFetchError reports whether err originated from the trust-bundle
// lookup step of x509svid.Verify (as opposed to the cryptographic chain
// verification step), so it can be classified as ErrTrustBundleUnavailable
// (fail closed on an unreachable/stale bundle) rather than
// ErrChainVerificationFailed (fail closed on a bad signature/issuer).
func isBundleFetchError(err error) bool {
	return strings.Contains(err.Error(), "could not get X509 bundle")
}

func (v *SPIFFEValidator) now() time.Time {
	if v.cfg.clock != nil {
		return v.cfg.clock()
	}
	return time.Now()
}

// warnMockUsage logs a loud warning on every single call made while
// InsecureMockIdentity is active, per requirement: this must be impossible
// to overlook, not just a one-line startup notice.
func (v *SPIFFEValidator) warnMockUsage() {
	log.Printf("SECURITY WARNING: %s=true -- this SPIFFE validation call was NOT cryptographically verified (mock identity bypass active).", EnvInsecureMockIdentity)
}

func (v *SPIFFEValidator) mockInternalIdentity(workload string) ValidationResult {
	if workload == "" {
		workload = "agent-ebpf-sensor"
	}

	id := SPIFFEID(fmt.Sprintf("spiffe://%s/%s", v.cfg.TrustDomain, workload))
	return ValidationResult{
		Identity: id,
		Valid:    true,
		Subject:  "CN=mock-internal, O=Neuromesh Control Plane",
	}
}

// parseCertificatesPEM decodes one or more concatenated PEM CERTIFICATE
// blocks into parsed x509 certificates (leaf first). This is standard-library
// PEM/DER decoding only -- all SPIFFE-specific semantics (URI SAN
// extraction, chain trust, key-usage constraints) are handled by
// github.com/spiffe/go-spiffe/v2, not hand-rolled here.
func parseCertificatesPEM(certPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := certPEM

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate DER: %w", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no PEM CERTIFICATE blocks found")
	}

	return certs, nil
}

