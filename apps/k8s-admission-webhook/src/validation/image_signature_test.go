package validation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// fakeVerifier is an in-memory ImageVerifier used to exercise the admission
// decision logic in Validator without hitting a real container registry or
// real Sigstore/Rekor infrastructure. The real cryptographic verification
// primitives (public key parsing, signature checking) are exercised
// separately in verifier_test.go against actual generated key material.
type fakeVerifier struct {
	// results maps an image reference to the VerificationResult that should
	// be returned for it (nil error).
	results map[string]VerificationResult
	// unreachableErr, if set, is returned for every call regardless of
	// results, simulating the trust anchor (registry/Rekor/Fulcio) being
	// unreachable.
	unreachableErr error
}

func (f *fakeVerifier) VerifyImage(_ context.Context, imageRef string) (*VerificationResult, error) {
	if f.unreachableErr != nil {
		return nil, f.unreachableErr
	}

	result, ok := f.results[imageRef]
	if !ok {
		return nil, errors.New("no valid signature found for image (unsigned or tampered)")
	}

	return &result, nil
}

func admissionRequestForPod(t *testing.T, pod corev1.Pod, op admissionv1.Operation) *admissionv1.AdmissionRequest {
	t.Helper()

	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}

	return &admissionv1.AdmissionRequest{
		UID:       "uid-test",
		Kind:      metav1.GroupVersionKind{Kind: "Pod"},
		Operation: op,
		Object:    runtime.RawExtension{Raw: raw},
	}
}

func samplePod(image string) corev1.Pod {
	return corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
	}
}

func TestValidateAdmissionReview_AllowsCorrectlySignedImage(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{
		results: map[string]VerificationResult{
			"registry.example.com/app:v1": {
				ImageRef:       "registry.example.com/app:v1",
				Digest:         "sha256:abc123",
				Verified:       true,
				Mode:           VerifyModeKey,
				SignerIdentity: "cosign-static-key:sha256:deadbeef",
			},
		},
	}
	validator := NewValidator(verifier)

	resp := validator.ValidateAdmissionReview(
		context.Background(),
		admissionRequestForPod(t, samplePod("registry.example.com/app:v1"), admissionv1.Create),
	)

	if !resp.Allowed {
		t.Fatalf("expected correctly-signed image to be allowed, got denial: %+v", resp.Result)
	}
}

func TestValidateAdmissionReview_DeniesUnsignedImage(t *testing.T) {
	t.Parallel()

	// No entry for this image in the fake verifier's results -> simulates an
	// unsigned image.
	verifier := &fakeVerifier{results: map[string]VerificationResult{}}
	validator := NewValidator(verifier)

	resp := validator.ValidateAdmissionReview(
		context.Background(),
		admissionRequestForPod(t, samplePod("registry.example.com/unsigned:v1"), admissionv1.Create),
	)

	if resp.Allowed {
		t.Fatal("expected unsigned image to be denied")
	}
	if resp.Result == nil || resp.Result.Reason != metav1.StatusReasonForbidden {
		t.Fatalf("expected Forbidden reason, got: %+v", resp.Result)
	}
}

func TestValidateAdmissionReview_DeniesTamperedOrWrongKeySignature(t *testing.T) {
	t.Parallel()

	// Verifier explicitly returns Verified: false with no error -- e.g. a
	// signature was found but did not match the configured key, or claim
	// verification (digest mismatch) failed downstream.
	verifier := &fakeVerifier{
		results: map[string]VerificationResult{
			"registry.example.com/tampered:v1": {
				ImageRef: "registry.example.com/tampered:v1",
				Verified: false,
			},
		},
	}
	validator := NewValidator(verifier)

	resp := validator.ValidateAdmissionReview(
		context.Background(),
		admissionRequestForPod(t, samplePod("registry.example.com/tampered:v1"), admissionv1.Create),
	)

	if resp.Allowed {
		t.Fatal("expected tampered/wrong-key image to be denied")
	}
}

func TestValidateAdmissionReview_DeniesOnTrustAnchorUnreachable(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{unreachableErr: errors.New("dial tcp registry.example.com:443: connection refused")}
	validator := NewValidator(verifier)

	resp := validator.ValidateAdmissionReview(
		context.Background(),
		admissionRequestForPod(t, samplePod("registry.example.com/app:v1"), admissionv1.Create),
	)

	if resp.Allowed {
		t.Fatal("expected admission to be denied (fail-closed) when the trust anchor is unreachable, not allowed")
	}
}

func TestValidateAdmissionReview_IgnoresNonPodKinds(t *testing.T) {
	t.Parallel()

	// A verifier that always errors: if this were consulted, the request
	// would be denied. Passing through a non-Pod kind must never reach it.
	verifier := &fakeVerifier{unreachableErr: errors.New("verifier should not have been called")}
	validator := NewValidator(verifier)

	resp := validator.ValidateAdmissionReview(context.Background(), &admissionv1.AdmissionRequest{
		UID:       "uid-configmap",
		Kind:      metav1.GroupVersionKind{Kind: "ConfigMap"},
		Operation: admissionv1.Create,
	})

	if !resp.Allowed {
		t.Fatalf("expected non-Pod resources to pass through unaffected, got: %+v", resp.Result)
	}
}

func TestValidateAdmissionReview_RejectsMalformedPodPayload(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{unreachableErr: errors.New("verifier should not have been called")}
	validator := NewValidator(verifier)

	resp := validator.ValidateAdmissionReview(context.Background(), &admissionv1.AdmissionRequest{
		UID:       "uid-bad",
		Kind:      metav1.GroupVersionKind{Kind: "Pod"},
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: []byte("not json")},
	})

	if resp.Allowed {
		t.Fatal("expected malformed Pod payload to be rejected")
	}
	if resp.Result == nil || resp.Result.Reason != metav1.StatusReasonBadRequest {
		t.Fatalf("expected BadRequest reason, got: %+v", resp.Result)
	}
}

func TestValidateAdmissionReview_DeniesWhenAnyContainerFailsVerification(t *testing.T) {
	t.Parallel()

	// Only the first container's image is signed; the second is not. The
	// whole pod must be denied even though one image verified fine.
	verifier := &fakeVerifier{
		results: map[string]VerificationResult{
			"registry.example.com/signed:v1": {ImageRef: "registry.example.com/signed:v1", Verified: true, Mode: VerifyModeKey},
		},
	}
	validator := NewValidator(verifier)

	pod := corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "registry.example.com/signed:v1"},
				{Name: "sidecar", Image: "registry.example.com/unsigned:v1"},
			},
		},
	}

	resp := validator.ValidateAdmissionReview(context.Background(), admissionRequestForPod(t, pod, admissionv1.Create))

	if resp.Allowed {
		t.Fatal("expected pod with any unverified container image to be denied")
	}
}

func TestCollectContainerImages(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Image: "init:v1"}},
			Containers:     []corev1.Container{{Image: "app:v1"}, {Image: "sidecar:v1"}},
			EphemeralContainers: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Image: "debug:v1"}},
			},
		},
	}

	got := collectContainerImages(pod)
	want := []string{"init:v1", "app:v1", "sidecar:v1", "debug:v1"}

	if len(got) != len(want) {
		t.Fatalf("expected %d images, got %d: %v", len(want), len(got), got)
	}
	for i, image := range want {
		if got[i] != image {
			t.Errorf("index %d: expected %q, got %q", i, image, got[i])
		}
	}
}
