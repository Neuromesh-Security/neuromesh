package identity

import (
	"testing"
)

func TestSPIFFEValidator_MockInternalReturnsValidIdentity(t *testing.T) {
	t.Parallel()

	validator := NewSPIFFEValidator(DefaultConfig())

	result, err := validator.ValidateCertificatePEM([]byte("mock-pem"))
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

func TestSPIFFEValidator_RejectsEmptyPEMWhenNotMocking(t *testing.T) {
	t.Parallel()

	validator := NewSPIFFEValidator(ValidatorConfig{
		TrustDomain:  "neuromesh.security",
		MockInternal: false,
	})

	_, err := validator.ValidateCertificatePEM(nil)
	if err == nil {
		t.Fatal("expected error for empty PEM")
	}
}
