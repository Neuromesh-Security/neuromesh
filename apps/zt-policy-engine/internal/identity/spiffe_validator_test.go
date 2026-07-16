package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// --- test fixtures: a minimal, real X.509 CA + SVID-issuance helper -------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:              time.Now().Add(-1 * time.Hour),
		NotAfter:               time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	return testCA{cert: cert, key: key}
}

// issueLeaf signs a leaf X.509-SVID under ca with the given SPIFFE ID and
// validity window, returning both the parsed certificate and its PEM
// encoding (as ValidateCertificatePEM would receive over the wire).
func (ca testCA) issueLeaf(t *testing.T, spiffeIDStr string, notBefore, notAfter time.Time) (*x509.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	uri, err := url.Parse(spiffeIDStr)
	if err != nil {
		t.Fatalf("parse SPIFFE ID %q: %v", spiffeIDStr, err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{uri},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes
}

func mustTrustDomain(t *testing.T, name string) spiffeid.TrustDomain {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(name)
	if err != nil {
		t.Fatalf("trust domain %q: %v", name, err)
	}
	return td
}

// errBundleSource always fails the bundle lookup, simulating an
// unreachable/stale trust bundle (e.g. Workload API down, static file
// deleted out from under a running process).
type errBundleSource struct {
	err error
}

func (e errBundleSource) GetX509BundleForTrustDomain(_ spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return nil, e.err
}

// --- mock-identity bypass (explicit opt-in only) ---------------------------

func TestSPIFFEValidator_MockIdentityDisabledByDefault(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	if cfg.InsecureMockIdentity {
		t.Fatal("DefaultConfig() must not enable InsecureMockIdentity")
	}
	if cfg.TrustBundleMode != "" {
		t.Fatalf("DefaultConfig() must not select a TrustBundleMode by default, got %q", cfg.TrustBundleMode)
	}
}

func TestSPIFFEValidator_MockIdentity_OnlyWhenExplicitlyEnabled(t *testing.T) {
	t.Parallel()

	validator, err := NewSPIFFEValidator(context.Background(), ValidatorConfig{
		TrustDomain:          "neuromesh.security",
		InsecureMockIdentity: true,
	})
	if err != nil {
		t.Fatalf("NewSPIFFEValidator: %v", err)
	}

	result, err := validator.ValidateCertificatePEM([]byte("anything, even garbage"))
	if err != nil {
		t.Fatalf("ValidateCertificatePEM: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected mock validation to succeed")
	}
	if result.Identity.String() != "spiffe://neuromesh.security/agent-ebpf-sensor" {
		t.Fatalf("unexpected identity: %s", result.Identity)
	}
}

// --- real chain validation: happy path -------------------------------------

func TestSPIFFEValidator_AllowsValidCertAgainstMatchingStaticTrustBundle(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "neuromesh-test-ca")
	_, leafPEM := ca.issueLeaf(t, "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
		time.Now().Add(-5*time.Minute), time.Now().Add(time.Hour))

	bundlePath := writeBundleFile(t, ca.cert)

	validator, err := NewSPIFFEValidator(context.Background(), ValidatorConfig{
		TrustDomain:     "neuromesh.security",
		TrustBundleMode: TrustBundleModeStaticFile,
		BundlePath:      bundlePath,
	})
	if err != nil {
		t.Fatalf("NewSPIFFEValidator: %v", err)
	}
	t.Cleanup(func() { _ = validator.Close() })

	result, err := validator.ValidateCertificatePEM(leafPEM)
	if err != nil {
		t.Fatalf("ValidateCertificatePEM: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected valid signed cert to pass")
	}
	if result.Identity.String() != "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor" {
		t.Fatalf("unexpected identity: %s", result.Identity)
	}
}

func writeBundleFile(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()

	var buf []byte
	for _, cert := range certs {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write bundle file: %v", err)
	}
	return path
}

// --- real chain validation: rejection scenarios ----------------------------

func TestSPIFFEValidator_DeniesWrongTrustDomain(t *testing.T) {
	t.Parallel()

	trustedCA := newTestCA(t, "trusted-ca")
	// Leaf claims a *different* trust domain than the validator trusts, even
	// though it happens to be signed by the trusted CA in this fixture --
	// the trust-domain check must fire before any chain verification.
	_, leafPEM := trustedCA.issueLeaf(t, "spiffe://intruder.example/ns/default/sa/attacker",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	v := &SPIFFEValidator{
		cfg:          ValidatorConfig{TrustDomain: "neuromesh.security"},
		trustDomain:  mustTrustDomain(t, "neuromesh.security"),
		bundleSource: x509bundle.FromX509Authorities(mustTrustDomain(t, "neuromesh.security"), []*x509.Certificate{trustedCA.cert}),
	}

	_, err := v.ValidateCertificatePEM(leafPEM)
	if err == nil {
		t.Fatal("expected error for wrong trust domain")
	}
	if !errors.Is(err, ErrTrustDomainMismatch) {
		t.Fatalf("expected ErrTrustDomainMismatch, got: %v", err)
	}
}

func TestSPIFFEValidator_DeniesUntrustedSigner(t *testing.T) {
	t.Parallel()

	trustedCA := newTestCA(t, "trusted-ca")
	untrustedCA := newTestCA(t, "untrusted-ca")

	// Same trust domain string as configured, but signed by a CA that is
	// NOT in the trust bundle -- this exercises the actual cryptographic
	// chain check (the previously-TODO'd verification), not just ID parsing.
	_, leafPEM := untrustedCA.issueLeaf(t, "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	v := &SPIFFEValidator{
		cfg:          ValidatorConfig{TrustDomain: "neuromesh.security"},
		trustDomain:  mustTrustDomain(t, "neuromesh.security"),
		bundleSource: x509bundle.FromX509Authorities(mustTrustDomain(t, "neuromesh.security"), []*x509.Certificate{trustedCA.cert}),
	}

	_, err := v.ValidateCertificatePEM(leafPEM)
	if err == nil {
		t.Fatal("expected error for untrusted signer")
	}
	if !errors.Is(err, ErrChainVerificationFailed) {
		t.Fatalf("expected ErrChainVerificationFailed, got: %v", err)
	}
}

func TestSPIFFEValidator_DeniesExpiredCertificate(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "trusted-ca")
	_, leafPEM := ca.issueLeaf(t, "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))

	v := &SPIFFEValidator{
		cfg:          ValidatorConfig{TrustDomain: "neuromesh.security"},
		trustDomain:  mustTrustDomain(t, "neuromesh.security"),
		bundleSource: x509bundle.FromX509Authorities(mustTrustDomain(t, "neuromesh.security"), []*x509.Certificate{ca.cert}),
	}

	_, err := v.ValidateCertificatePEM(leafPEM)
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
	if !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("expected ErrCertificateExpired, got: %v", err)
	}
}

func TestSPIFFEValidator_DeniesNotYetValidCertificate(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "trusted-ca")
	_, leafPEM := ca.issueLeaf(t, "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
		time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))

	v := &SPIFFEValidator{
		cfg:          ValidatorConfig{TrustDomain: "neuromesh.security"},
		trustDomain:  mustTrustDomain(t, "neuromesh.security"),
		bundleSource: x509bundle.FromX509Authorities(mustTrustDomain(t, "neuromesh.security"), []*x509.Certificate{ca.cert}),
	}

	_, err := v.ValidateCertificatePEM(leafPEM)
	if err == nil {
		t.Fatal("expected error for not-yet-valid certificate")
	}
	if !errors.Is(err, ErrCertificateNotYetValid) {
		t.Fatalf("expected ErrCertificateNotYetValid, got: %v", err)
	}
}

func TestSPIFFEValidator_DeniesMalformedCertificate(t *testing.T) {
	t.Parallel()

	v := &SPIFFEValidator{
		cfg:         ValidatorConfig{TrustDomain: "neuromesh.security"},
		trustDomain: mustTrustDomain(t, "neuromesh.security"),
	}

	_, err := v.ValidateCertificatePEM([]byte("this is not a certificate, just garbage bytes"))
	if err == nil {
		t.Fatal("expected error for malformed certificate")
	}
	if !errors.Is(err, ErrMalformedCertificate) {
		t.Fatalf("expected ErrMalformedCertificate, got: %v", err)
	}
}

func TestSPIFFEValidator_DeniesNoCertificatePresented(t *testing.T) {
	t.Parallel()

	v := &SPIFFEValidator{
		cfg:         ValidatorConfig{TrustDomain: "neuromesh.security"},
		trustDomain: mustTrustDomain(t, "neuromesh.security"),
	}

	for _, name := range []string{"nil", "empty"} {
		var certPEM []byte
		if name == "empty" {
			certPEM = []byte{}
		}
		_, err := v.ValidateCertificatePEM(certPEM)
		if err == nil {
			t.Fatalf("%s: expected error when no certificate is presented", name)
		}
		if !errors.Is(err, ErrNoCertificatePresented) {
			t.Fatalf("%s: expected ErrNoCertificatePresented, got: %v", name, err)
		}
	}
}

func TestSPIFFEValidator_ValidateCertificate_NilIsFailClosed(t *testing.T) {
	t.Parallel()

	v := &SPIFFEValidator{
		cfg:         ValidatorConfig{TrustDomain: "neuromesh.security"},
		trustDomain: mustTrustDomain(t, "neuromesh.security"),
	}

	_, err := v.ValidateCertificate(nil)
	if !errors.Is(err, ErrNoCertificatePresented) {
		t.Fatalf("expected ErrNoCertificatePresented, got: %v", err)
	}
}

func TestSPIFFEValidator_DeniesOnTrustBundleUnreachable(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "trusted-ca")
	_, leafPEM := ca.issueLeaf(t, "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	v := &SPIFFEValidator{
		cfg:          ValidatorConfig{TrustDomain: "neuromesh.security"},
		trustDomain:  mustTrustDomain(t, "neuromesh.security"),
		bundleSource: errBundleSource{err: errors.New("connection refused: workload API socket unreachable")},
	}

	result, err := v.ValidateCertificatePEM(leafPEM)
	if err == nil {
		t.Fatal("expected error when trust bundle is unreachable")
	}
	if result.Valid {
		t.Fatal("trust bundle being unreachable must never fail OPEN")
	}
	if !errors.Is(err, ErrTrustBundleUnavailable) {
		t.Fatalf("expected ErrTrustBundleUnavailable, got: %v", err)
	}
}

func TestSPIFFEValidator_DeniesSPIFFEIDNotMatchingExpectedPattern(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "trusted-ca")
	_, leafPEM := ca.issueLeaf(t, "spiffe://neuromesh.security/ns/kube-system/sa/unexpected-workload",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	v := &SPIFFEValidator{
		cfg: ValidatorConfig{
			TrustDomain:       "neuromesh.security",
			ExpectedIDPattern: regexp.MustCompile(`^/ns/default/sa/agent-ebpf-sensor$`),
		},
		trustDomain:  mustTrustDomain(t, "neuromesh.security"),
		bundleSource: x509bundle.FromX509Authorities(mustTrustDomain(t, "neuromesh.security"), []*x509.Certificate{ca.cert}),
	}

	_, err := v.ValidateCertificatePEM(leafPEM)
	if err == nil {
		t.Fatal("expected error for SPIFFE ID path not matching expected pattern")
	}
	if !errors.Is(err, ErrIDPatternMismatch) {
		t.Fatalf("expected ErrIDPatternMismatch, got: %v", err)
	}
}

func TestSPIFFEValidator_AllowsSPIFFEIDMatchingExpectedPattern(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, "trusted-ca")
	_, leafPEM := ca.issueLeaf(t, "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	v := &SPIFFEValidator{
		cfg: ValidatorConfig{
			TrustDomain:       "neuromesh.security",
			ExpectedIDPattern: regexp.MustCompile(`^/ns/default/sa/agent-ebpf-sensor$`),
		},
		trustDomain:  mustTrustDomain(t, "neuromesh.security"),
		bundleSource: x509bundle.FromX509Authorities(mustTrustDomain(t, "neuromesh.security"), []*x509.Certificate{ca.cert}),
	}

	result, err := v.ValidateCertificatePEM(leafPEM)
	if err != nil {
		t.Fatalf("ValidateCertificatePEM: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected matching SPIFFE ID pattern to pass")
	}
}

// --- constructor / configuration misuse ------------------------------------

func TestNewSPIFFEValidator_RejectsUnknownTrustBundleMode(t *testing.T) {
	t.Parallel()

	_, err := NewSPIFFEValidator(context.Background(), ValidatorConfig{
		TrustDomain:     "neuromesh.security",
		TrustBundleMode: "not-a-real-mode",
	})
	if !errors.Is(err, ErrInvalidValidatorConfig) {
		t.Fatalf("expected ErrInvalidValidatorConfig, got: %v", err)
	}
}

func TestNewSPIFFEValidator_RejectsEmptyTrustBundleModeWhenNotMocking(t *testing.T) {
	t.Parallel()

	_, err := NewSPIFFEValidator(context.Background(), ValidatorConfig{
		TrustDomain: "neuromesh.security",
	})
	if !errors.Is(err, ErrInvalidValidatorConfig) {
		t.Fatalf("expected ErrInvalidValidatorConfig for unset TrustBundleMode, got: %v", err)
	}
}

func TestNewSPIFFEValidator_StaticFileModeRequiresBundlePath(t *testing.T) {
	t.Parallel()

	_, err := NewSPIFFEValidator(context.Background(), ValidatorConfig{
		TrustDomain:     "neuromesh.security",
		TrustBundleMode: TrustBundleModeStaticFile,
	})
	if !errors.Is(err, ErrInvalidValidatorConfig) {
		t.Fatalf("expected ErrInvalidValidatorConfig, got: %v", err)
	}
}

func TestNewSPIFFEValidator_StaticFileModeFailsClosedOnMissingBundleFile(t *testing.T) {
	t.Parallel()

	_, err := NewSPIFFEValidator(context.Background(), ValidatorConfig{
		TrustDomain:     "neuromesh.security",
		TrustBundleMode: TrustBundleModeStaticFile,
		BundlePath:      filepath.Join(t.TempDir(), "does-not-exist.pem"),
	})
	if !errors.Is(err, ErrTrustBundleUnavailable) {
		t.Fatalf("expected ErrTrustBundleUnavailable, got: %v", err)
	}
}

func TestNewSPIFFEValidator_StaticFileModeFailsClosedOnEmptyBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "empty-bundle.pem")
	if err := os.WriteFile(path, []byte("# no certificates here\n"), 0o600); err != nil {
		t.Fatalf("write empty bundle: %v", err)
	}

	_, err := NewSPIFFEValidator(context.Background(), ValidatorConfig{
		TrustDomain:     "neuromesh.security",
		TrustBundleMode: TrustBundleModeStaticFile,
		BundlePath:      path,
	})
	if !errors.Is(err, ErrTrustBundleUnavailable) {
		t.Fatalf("expected ErrTrustBundleUnavailable for empty bundle, got: %v", err)
	}
}

// --- env-driven configuration -----------------------------------------------

func TestConfigFromEnv_DoesNotEnableMockByDefault(t *testing.T) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.InsecureMockIdentity {
		t.Fatal("ConfigFromEnv must not enable InsecureMockIdentity unless NEUROMESH_INSECURE_MOCK_IDENTITY=true")
	}
}

func TestConfigFromEnv_MockRequiresExactTrueValue(t *testing.T) {
	t.Setenv(EnvInsecureMockIdentity, "yes-please")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.InsecureMockIdentity {
		t.Fatal("only the exact value \"true\" must enable InsecureMockIdentity")
	}
}

func TestConfigFromEnv_MockEnabledExplicitly(t *testing.T) {
	t.Setenv(EnvInsecureMockIdentity, "true")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if !cfg.InsecureMockIdentity {
		t.Fatal("expected InsecureMockIdentity to be true when NEUROMESH_INSECURE_MOCK_IDENTITY=true")
	}
}

func TestConfigFromEnv_RejectsInvalidExpectedIDPattern(t *testing.T) {
	t.Setenv("NEUROMESH_SPIFFE_EXPECTED_ID_PATTERN", "[invalid-regex(")
	_, err := ConfigFromEnv()
	if !errors.Is(err, ErrInvalidValidatorConfig) {
		t.Fatalf("expected ErrInvalidValidatorConfig, got: %v", err)
	}
}
