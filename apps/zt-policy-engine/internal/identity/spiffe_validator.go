package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
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

// ValidatorConfig holds trust-domain settings for SPIFFE validation.
type ValidatorConfig struct {
	TrustDomain string
	// BundlePath will point to a SPIFFE bundle on disk once mTLS is wired.
	BundlePath string
	// MockInternal validates all presented material as a trusted internal workload.
	MockInternal bool
}

// DefaultConfig returns development defaults for the control plane sprint.
func DefaultConfig() ValidatorConfig {
	return ValidatorConfig{
		TrustDomain:  "neuromesh.security",
		MockInternal: true,
	}
}

// SPIFFEValidator verifies workload identities presented via mTLS x509 SVIDs.
//
// Production path: validate certificate chain against a SPIFFE bundle, extract
// the URI SAN, and enforce trust-domain policy. Sprint path: mock internal
// components to unblock Fast Path integration without SPIRE deployment.
type SPIFFEValidator struct {
	cfg ValidatorConfig
}

// NewSPIFFEValidator constructs a validator from the supplied configuration.
func NewSPIFFEValidator(cfg ValidatorConfig) *SPIFFEValidator {
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = "neuromesh.security"
	}
	return &SPIFFEValidator{cfg: cfg}
}

// ValidateCertificatePEM verifies an x509 SVID presented as PEM-encoded DER bytes.
func (v *SPIFFEValidator) ValidateCertificatePEM(certPEM []byte) (ValidationResult, error) {
	if len(certPEM) == 0 {
		return ValidationResult{}, errors.New("empty certificate PEM")
	}

	if v.cfg.MockInternal {
		return v.mockInternalIdentity("agent-ebpf-sensor"), nil
	}

	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return ValidationResult{}, err
	}

	return v.validateCertificate(cert)
}

// ValidateCertificate verifies a parsed x509 certificate chain leaf SVID.
func (v *SPIFFEValidator) ValidateCertificate(cert *x509.Certificate) (ValidationResult, error) {
	if cert == nil {
		return ValidationResult{}, errors.New("nil certificate")
	}

	if v.cfg.MockInternal {
		return v.mockInternalIdentity(extractSPIFFEID(cert)), nil
	}

	return v.validateCertificate(cert)
}

func (v *SPIFFEValidator) validateCertificate(cert *x509.Certificate) (ValidationResult, error) {
	spiffeID := extractSPIFFEID(cert)
	if spiffeID == "" {
		return ValidationResult{
			Valid:   false,
			Subject: cert.Subject.String(),
		}, errors.New("certificate missing SPIFFE URI SAN")
	}

	// TODO: verify chain against SPIFFE bundle at v.cfg.BundlePath.
	return ValidationResult{
		Identity: SPIFFEID(spiffeID),
		Valid:    true,
		Subject:  cert.Subject.String(),
	}, nil
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

func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	// Sprint stub — real PEM parsing lands with mTLS listener wiring.
	return nil, errors.New("PEM parsing not implemented; enable MockInternal for sprint")
}

func extractSPIFFEID(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if uri != nil && uri.Scheme == "spiffe" {
			return uri.String()
		}
	}
	return ""
}
