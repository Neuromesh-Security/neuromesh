package validation

import (
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

const (
	// SignedAnnotation marks pods verified by future Cosign/Notary image signing.
	SignedAnnotation = "neuromesh.security/signed"
)

var (
	scheme  = runtime.NewScheme()
	decoder = serializer.NewCodecFactory(scheme).UniversalDeserializer()
)

func init() {
	_ = corev1.AddToScheme(scheme)
}

// ValidateAdmissionReview handles validating webhook requests for Pod resources.
func ValidateAdmissionReview(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
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

	if !isPodSigned(pod) {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: fmt.Sprintf(
				"pod rejected: missing required annotation %q (Cosign/Notary verification sprint mock)",
				SignedAnnotation,
			),
			Reason: metav1.StatusReasonForbidden,
		}
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

func isPodSigned(pod *corev1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}

	value, ok := pod.Annotations[SignedAnnotation]
	return ok && value == "true"
}
