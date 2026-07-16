package validation

import (
	"context"
	"fmt"
	"log"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

const (
	// SignedAnnotation was the original mock security gate: any pod author
	// could set this annotation themselves to grant their own pod admission,
	// so it provided no real security guarantee.
	//
	// Deprecated: the annotation is no longer consulted for the admission
	// decision -- real cryptographic verification (see verifier.go) is now
	// authoritative. The constant and annotation key are left in place only
	// in case some other consumer (dashboards, metadata tooling) still reads
	// this annotation; if nothing else references it, it should be removed
	// in a follow-up cleanup rather than being mistaken for a security control.
	SignedAnnotation = "neuromesh.security/signed"
)

var (
	scheme  = runtime.NewScheme()
	decoder = serializer.NewCodecFactory(scheme).UniversalDeserializer()
)

func init() {
	_ = corev1.AddToScheme(scheme)
}

// Validator performs Pod admission validation, including real cryptographic
// container image signature verification via the configured ImageVerifier.
type Validator struct {
	verifier ImageVerifier
}

// NewValidator constructs a Validator backed by the given ImageVerifier.
func NewValidator(verifier ImageVerifier) *Validator {
	return &Validator{verifier: verifier}
}

// ValidateAdmissionReview handles validating webhook requests for Pod resources.
//
// Fail-closed contract: any container image that cannot be positively,
// cryptographically verified -- whether due to a bad/missing signature, a
// wrong signing key, or the trust anchor (registry, Rekor, Fulcio) being
// unreachable -- results in admission being denied. There is no code path
// that falls back to allowing a pod when verification could not be completed.
func (val *Validator) ValidateAdmissionReview(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req == nil {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: "missing admission request",
				Reason:  metav1.StatusReasonBadRequest,
			},
		}
	}

	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	if req.Kind.Kind != "Pod" {
		return response
	}

	switch req.Operation {
	case admissionv1.Create, admissionv1.Update:
	default:
		return response
	}

	pod, err := decodePod(req.Object)
	if err != nil {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: fmt.Sprintf("failed to decode Pod: %v", err),
			Reason:  metav1.StatusReasonBadRequest,
		}
		return response
	}

	images := collectContainerImages(pod)
	if len(images) == 0 {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: "pod rejected: no container images present to verify",
			Reason:  metav1.StatusReasonForbidden,
		}
		return response
	}

	for _, image := range images {
		result, verifyErr := val.verifier.VerifyImage(ctx, image)
		if verifyErr != nil || result == nil || !result.Verified {
			reason := "verification returned no result"
			if verifyErr != nil {
				reason = verifyErr.Error()
			}

			log.Printf(
				"admission-webhook: DENY pod=%s/%s image=%q signature verification failed (fail-closed): %s",
				pod.Namespace, pod.Name, image, reason,
			)

			response.Allowed = false
			response.Result = &metav1.Status{
				Message: fmt.Sprintf(
					"pod rejected: image %q failed cryptographic signature verification: %s",
					image, reason,
				),
				Reason: metav1.StatusReasonForbidden,
			}
			return response
		}

		log.Printf(
			"admission-webhook: ALLOW pod=%s/%s image=%q digest=%s mode=%s signer=%q",
			pod.Namespace, pod.Name, image, result.Digest, result.Mode, result.SignerIdentity,
		)
	}

	return response
}

func decodePod(raw runtime.RawExtension) (*corev1.Pod, error) {
	if raw.Raw == nil {
		return nil, fmt.Errorf("empty object payload")
	}

	obj, _, err := decoder.Decode(raw.Raw, nil, nil)
	if err != nil {
		return nil, err
	}

	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("expected Pod, got %T", obj)
	}

	return pod, nil
}

// isPodSigned is DEAD CODE kept only so its removal shows up as an explicit,
// reviewable diff rather than a silent deletion (per review requirement: flag
// don't silently delete). It is no longer called anywhere -- the annotation
// it inspects carries no security meaning; see the SignedAnnotation doc
// comment above. TODO(neuromesh-security): delete this function (and,
// separately, decide whether SignedAnnotation itself should be removed or
// repurposed as non-authoritative metadata) once confirmed no other consumer
// depends on it.
//
//nolint:unused // intentionally retained dead code, see comment above
func isPodSigned(pod *corev1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}

	value, ok := pod.Annotations[SignedAnnotation]
	return ok && value == "true"
}

// collectContainerImages returns every container image reference on the pod
// spec (init containers, regular containers, and ephemeral debug containers)
// that must be verified before the pod can be admitted.
func collectContainerImages(pod *corev1.Pod) []string {
	images := make([]string, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers)+len(pod.Spec.EphemeralContainers))

	for _, c := range pod.Spec.InitContainers {
		images = append(images, c.Image)
	}
	for _, c := range pod.Spec.Containers {
		images = append(images, c.Image)
	}
	for _, c := range pod.Spec.EphemeralContainers {
		images = append(images, c.Image)
	}

	return images
}
