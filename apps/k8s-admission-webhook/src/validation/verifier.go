package validation

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// NOTE on dependency footprint (evaluated 2026-07-16): cosign/v2's own
// pkg/cosign.VerifyImageSignatures (the OCI registry signature-fetch +
// verify entry point we need) unconditionally pulls in AWS/Azure/GCP/Vault
// KMS SDKs (via its TSA-verification code path in verify.go), the Rekor
// generated client, and go-openapi/strfmt -> mongo-driver -- none of which
// this webhook uses (NEUROMESH_COSIGN_VERIFY_MODE=key only, IgnoreTlog=true).
// This is baked into that single file/package in cosign/v2 v2.6.3 with no
// build tags to exclude it (only pkcs11/pivkey hardware-token support is
// build-tag-gated), and github.com/sigstore/sigstore-go still explicitly
// does not support OCI/container-image verification as of this evaluation,
// so it cannot replace pkg/cosign here. This is an accepted, investigated
// trade-off, not an oversight -- see the dependency-footprint report from
// this date for the full "go mod why" trace. What COULD be (and was)
// trimmed: we call sigstore/sigstore's cryptoutils+signature primitives
// directly below instead of cosign/v2/pkg/signature.LoadPublicKeyRaw, which
// avoids that package's unconditional GitHub/GitLab key-reference client
// imports (pkg/cosign/git/{github,gitlab}) -- functionally identical, since
// LoadPublicKeyRaw is itself a two-line wrapper around these same calls.
//
// NOTE on the remaining Rekor CVE (evaluated 2026-07-16): Trivy flags
// github.com/sigstore/rekor v1.4.3 (CVE-2026-48702, HIGH, unbounded gzip
// decompression) with a fix in v1.5.2. This is a transitive, indirect
// dependency of cosign/v2 (see above) that this webhook never calls --
// IgnoreTlog=true means no Rekor client code path executes. Bumping it in
// isolation was evaluated (`go get github.com/sigstore/rekor@v1.5.2` +
// `go mod tidy`) and confirmed to re-pull the exact AWS/Azure/GCP/HashiVault
// KMS SDKs, tink-crypto, and google/trillian that the deliberate dependency
// reduction above removed, for a HIGH (not CRITICAL) finding in dead code
// that does not fail the CI Trivy gate (gate enforces CRITICAL only). This
// is an accepted, investigated trade-off, not an oversight.
//
// NOTE on GO-2026-5932 / golang.org/x/crypto/openpgp (evaluated 2026-07-18):
// govulncheck flags openpgp as reachable via cosign.VerifyImageSignatures.
// This is NOT Cosign "PGP signature mode" as a selectable feature -- it enters
// because cosign/v2/pkg/cosign/verify.go (same package as VerifyImageSignatures)
// unconditionally imports github.com/sigstore/rekor/pkg/types/rekord/v0.0.1,
// which pulls rekor/pkg/pki/pgp -> golang.org/x/crypto/openpgp. Confirmed with
// `go list -deps` on ./src/validation: the only third-party importer of
// openpgp* in this graph is rekor/pkg/pki/pgp; sigstore cryptoutils+signature
// alone do not pull it. There is no narrower public Cosign API / build tag that
// preserves OCI image verify without that package (unlike the LoadPublicKeyRaw
// trim above, which lived in a different package). IgnoreTlog=true skips
// runtime Rekor client use only -- it does not remove the compile-time import.
// This webhook never exercises the PGP path (NEUROMESH_COSIGN_VERIFY_MODE=key,
// Ed25519/ECDSA static key only). Fixed-in is N/A upstream for openpgp; clearing
// the finding would require forking cosign/v2 or waiting for an upstream package
// split / sigstore-go OCI verify. Accepted, investigated trade-off -- tracked in
// https://github.com/Neuromesh-Security/neuromesh/issues/48.

// Trust-root modes for image signature verification. "key" (static public key)
// is the default, production-ready mode. "keyless" (Fulcio short-lived cert +
// Rekor transparency log) is scaffolded but NOT fully implemented -- see
// CosignKeylessVerifier below.
const (
	VerifyModeKey     = "key"
	VerifyModeKeyless = "keyless"
)

// Environment variables controlling the active verifier. These are read once
// at process startup (NewVerifierFromEnv), mirroring the WEBHOOK_TLS_* pattern
// already used in main.go for the webhook's own serving certificate.
const (
	// EnvCosignVerifyMode selects the trust-root mode: "key" (default) or "keyless".
	EnvCosignVerifyMode = "NEUROMESH_COSIGN_VERIFY_MODE"

	// EnvCosignPublicKeyPath is the path to a PEM-encoded Cosign/Sigstore public
	// key, expected to be mounted from a Kubernetes Secret or ConfigMap, exactly
	// like the webhook's own TLS cert/key files.
	EnvCosignPublicKeyPath = "NEUROMESH_COSIGN_PUBLIC_KEY_PATH"

	// EnvCosignRequireTlog, when "true", additionally requires the signature to
	// have a matching Rekor transparency-log entry. Defaults to false because
	// static-key signing in private/enterprise pipelines commonly does not
	// (and often cannot) publish to the public-good Rekor instance.
	EnvCosignRequireTlog = "NEUROMESH_COSIGN_REQUIRE_TLOG"

	// EnvCosignKeylessIssuer / EnvCosignKeylessSubject configure the expected
	// Fulcio certificate OIDC issuer/subject for keyless mode. Both are required
	// if NEUROMESH_COSIGN_VERIFY_MODE=keyless is set.
	EnvCosignKeylessIssuer  = "NEUROMESH_COSIGN_KEYLESS_ISSUER"
	EnvCosignKeylessSubject = "NEUROMESH_COSIGN_KEYLESS_SUBJECT"

	// EnvCosignVerifyTimeoutSeconds bounds how long a single image's signature
	// verification (registry digest resolution + signature fetch + crypto
	// verification) may take before it is treated as a fail-closed denial.
	EnvCosignVerifyTimeoutSeconds = "NEUROMESH_COSIGN_VERIFY_TIMEOUT_SECONDS"

	// EnvCosignRegistryInsecure ("NEUROMESH_COSIGN_REGISTRY_INSECURE=true")
	// allows HTTP (non-TLS) registry access via name.Insecure. Explicit, loud
	// opt-in only — required for kind / air-gapped lab registries that speak
	// plain HTTP. Must never be set in a real deployment (absent from every
	// deploy/kubernetes/ manifest); activation logs a SECURITY WARNING at
	// startup. Defaults to unset / false — production registries must use HTTPS.
	EnvCosignRegistryInsecure = "NEUROMESH_COSIGN_REGISTRY_INSECURE"
)

const (
	defaultCosignPublicKeyPath = "/etc/webhook/cosign/cosign.pub"
	defaultVerifyTimeout       = 10 * time.Second
)

// VerificationResult carries the outcome of verifying a single container
// image reference, intended to be logged verbatim to the SOC/audit trail.
type VerificationResult struct {
	// ImageRef is the image reference exactly as specified on the container spec.
	ImageRef string
	// Digest is the resolved, immutable "sha256:..." digest that was actually
	// verified (never a mutable tag), per fail-closed anti-retag requirements.
	Digest string
	// Verified is true only when cryptographic verification succeeded.
	Verified bool
	// Mode is the trust-root mode that produced this result (VerifyModeKey or
	// VerifyModeKeyless).
	Mode string
	// SignerIdentity is a human-auditable identity for the verified signer:
	// the trusted public key's fingerprint in key mode, or the Fulcio
	// certificate Subject/Issuer in keyless mode.
	SignerIdentity string
}

// ImageVerifier resolves a container image reference to a pinned digest and
// cryptographically verifies its signature against a configured trust root.
//
// Implementations MUST fail closed: returning a non-nil error, or a
// VerificationResult with Verified == false, both mean "treat this image as
// unverified and deny admission." There is no implicit allow path.
type ImageVerifier interface {
	VerifyImage(ctx context.Context, imageRef string) (*VerificationResult, error)
}

// NewVerifierFromEnv builds the active ImageVerifier from environment
// configuration. It is called once at process startup; a returned error is
// intended to abort startup (fail closed on misconfiguration rather than
// silently serving traffic with no working trust root).
func NewVerifierFromEnv() (ImageVerifier, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(EnvCosignVerifyMode)))
	if mode == "" {
		mode = VerifyModeKey
	}

	timeout := defaultVerifyTimeout
	if raw := strings.TrimSpace(os.Getenv(EnvCosignVerifyTimeoutSeconds)); raw != "" {
		secs, err := strconv.Atoi(raw)
		if err != nil || secs <= 0 {
			return nil, fmt.Errorf("invalid %s value %q: must be a positive integer number of seconds", EnvCosignVerifyTimeoutSeconds, raw)
		}
		timeout = time.Duration(secs) * time.Second
	}

	switch mode {
	case VerifyModeKey:
		keyPath := os.Getenv(EnvCosignPublicKeyPath)
		if keyPath == "" {
			keyPath = defaultCosignPublicKeyPath
		}
		// Clean and require an absolute path so the configured trust-root
		// location can't be influenced by a relative/traversal-style value
		// (e.g. "../../etc/passwd") sneaking in through the environment.
		keyPath = filepath.Clean(keyPath)
		if !filepath.IsAbs(keyPath) {
			return nil, fmt.Errorf("%s must be an absolute path, got %q", EnvCosignPublicKeyPath, keyPath)
		}
		pemBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read cosign public key from %q: %w", keyPath, err)
		}
		requireTlog := strings.EqualFold(strings.TrimSpace(os.Getenv(EnvCosignRequireTlog)), "true")
		insecureRegistry := strings.EqualFold(strings.TrimSpace(os.Getenv(EnvCosignRegistryInsecure)), "true")
		if insecureRegistry {
			log.Printf("SECURITY WARNING: %s=true -- Cosign will accept plain-HTTP registry access (name.Insecure). Lab/kind only; never enable in production.", EnvCosignRegistryInsecure)
		}
		return NewCosignKeyVerifier(pemBytes, requireTlog, timeout, insecureRegistry)
	case VerifyModeKeyless:
		return NewCosignKeylessVerifier(
			strings.TrimSpace(os.Getenv(EnvCosignKeylessIssuer)),
			strings.TrimSpace(os.Getenv(EnvCosignKeylessSubject)),
			timeout,
		)
	default:
		return nil, fmt.Errorf("unsupported %s value %q (supported: %q, %q)", EnvCosignVerifyMode, mode, VerifyModeKey, VerifyModeKeyless)
	}
}

// CosignKeyVerifier verifies container image signatures published to an OCI
// registry (via `cosign sign --key`) against a single static public key. This
// is the default, fully-implemented trust-root mode.
type CosignKeyVerifier struct {
	verifier       signature.Verifier
	keyFingerprint string
	requireTlog    bool
	timeout        time.Duration
	insecure       bool
	registryOpts   []remote.Option
}

// NewCosignKeyVerifier constructs a CosignKeyVerifier from a PEM-encoded
// public key. The key is parsed once up front so misconfiguration is caught
// at startup rather than on the first admission request.
//
// insecureRegistry enables HTTP registry access (name.Insecure). Leave false
// for production HTTPS registries; set true only for kind/lab HTTP registries.
func NewCosignKeyVerifier(publicKeyPEM []byte, requireTlog bool, timeout time.Duration, insecureRegistry bool) (*CosignKeyVerifier, error) {
	// Equivalent to cosign/v2/pkg/signature.LoadPublicKeyRaw, called directly
	// against the lower-level sigstore/sigstore packages -- see the NOTE
	// above the import block for why.
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse cosign/sigstore public key: %w", err)
	}
	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("load signature verifier: %w", err)
	}

	fingerprint := sha256.Sum256(publicKeyPEM)

	return &CosignKeyVerifier{
		verifier:       verifier,
		keyFingerprint: hex.EncodeToString(fingerprint[:]),
		requireTlog:    requireTlog,
		timeout:        timeout,
		insecure:       insecureRegistry,
		registryOpts:   []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
	}, nil
}

// VerifyImage resolves imageRef to an immutable digest and verifies its
// Cosign signature against the configured static public key. Any failure
// (parse error, unresolvable digest, registry unreachable, no signature,
// signature does not match the key) is returned as a non-nil error; callers
// MUST treat that as a denial, never as an implicit allow.
func (v *CosignKeyVerifier) VerifyImage(ctx context.Context, imageRef string) (*VerificationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	digestRef, err := resolveImageDigest(ctx, imageRef, v.insecure, v.registryOpts...)
	if err != nil {
		return nil, fmt.Errorf("resolve image digest: %w", err)
	}

	checkOpts := &cosign.CheckOpts{
		SigVerifier:         v.verifier,
		ClaimVerifier:       cosign.SimpleClaimVerifier,
		IgnoreTlog:          !v.requireTlog,
		RegistryClientOpts:  []ociremote.Option{ociremote.WithRemoteOptions(v.registryOpts...)},
		IgnoreSCT:           true,
	}

	sigs, _, err := cosign.VerifyImageSignatures(ctx, digestRef, checkOpts)
	if err != nil {
		return nil, fmt.Errorf("cosign signature verification failed for %s: %w", digestRef.String(), err)
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("no valid cosign signatures found for %s", digestRef.String())
	}

	return &VerificationResult{
		ImageRef:       imageRef,
		Digest:         digestRef.DigestStr(),
		Verified:       true,
		Mode:           VerifyModeKey,
		SignerIdentity: fmt.Sprintf("cosign-static-key:sha256:%s", v.keyFingerprint),
	}, nil
}

// CosignKeylessVerifier is a SCAFFOLD for Sigstore keyless verification
// (Fulcio-issued short-lived certificate + Rekor transparency-log inclusion
// proof, matched against an expected OIDC issuer/subject identity).
//
// TODO(neuromesh-security): this mode is not yet fully implemented. A real
// implementation needs, at minimum: a TUF client to fetch/refresh the
// Sigstore public-good (or private) trusted root bundle (Fulcio root/intermediate
// certs, Rekor + CT log public keys), wiring that root into
// cosign.CheckOpts.TrustedMaterial (or RootCerts/CTLogPubKeys/RekorPubKeys for
// the legacy path), and a decision on trusted-root refresh/caching strategy
// inside a webhook request path with a strict verification timeout. Until
// that is implemented, VerifyImage deliberately returns an error on every
// call -- so selecting keyless mode fails admission closed and loudly,
// instead of silently no-op'ing to "allow".
type CosignKeylessVerifier struct {
	identity cosign.Identity
	timeout  time.Duration
}

// NewCosignKeylessVerifier validates keyless configuration up front. It does
// NOT perform any trust-root fetch (see TODO on CosignKeylessVerifier).
func NewCosignKeylessVerifier(issuer, subject string, timeout time.Duration) (*CosignKeylessVerifier, error) {
	if issuer == "" || subject == "" {
		return nil, fmt.Errorf(
			"keyless verification requires both %s and %s to be set",
			EnvCosignKeylessIssuer, EnvCosignKeylessSubject,
		)
	}
	return &CosignKeylessVerifier{
		identity: cosign.Identity{Issuer: issuer, Subject: subject},
		timeout:  timeout,
	}, nil
}

// VerifyImage always fails closed: see the TODO on CosignKeylessVerifier.
func (v *CosignKeylessVerifier) VerifyImage(_ context.Context, imageRef string) (*VerificationResult, error) {
	return nil, fmt.Errorf(
		"keyless cosign verification (issuer=%q subject=%q) is scaffolded but not implemented; refusing to admit %q (fail-closed)",
		v.identity.Issuer, v.identity.Subject, imageRef,
	)
}

// resolveImageDigest pins imageRef to an immutable digest reference before
// any signature lookup happens, so a signature check can never be bypassed by
// re-tagging the same tag to a different, unsigned/malicious image after the
// fact. If imageRef already carries a digest (repo@sha256:...), it is used
// as-is; otherwise the digest is resolved live from the registry.
//
// When insecure is true, references are parsed with name.Insecure so plain
// HTTP registries (kind/lab) are reachable; production must keep this false.
func resolveImageDigest(ctx context.Context, imageRef string, insecure bool, opts ...remote.Option) (name.Digest, error) {
	nameOpts := registryNameOptions(insecure)
	ref, err := name.ParseReference(imageRef, nameOpts...)
	if err != nil {
		return name.Digest{}, fmt.Errorf("parse image reference %q: %w", imageRef, err)
	}

	if digestRef, ok := ref.(name.Digest); ok {
		return digestRef, nil
	}

	headOpts := append([]remote.Option{remote.WithContext(ctx)}, opts...)
	descriptor, err := remote.Head(ref, headOpts...)
	if err != nil {
		return name.Digest{}, fmt.Errorf("resolve digest for %q from registry: %w", imageRef, err)
	}

	digestRef, err := name.NewDigest(fmt.Sprintf("%s@%s", ref.Context().Name(), descriptor.Digest.String()), nameOpts...)
	if err != nil {
		return name.Digest{}, fmt.Errorf("build digest reference for %q: %w", imageRef, err)
	}

	return digestRef, nil
}

func registryNameOptions(insecure bool) []name.Option {
	if !insecure {
		return nil
	}
	return []name.Option{name.Insecure}
}
