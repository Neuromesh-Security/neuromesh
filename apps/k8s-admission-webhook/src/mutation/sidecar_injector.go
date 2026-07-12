package mutation

import (
	"encoding/json"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

const (
	sidecarContainerName = "neuromesh-security-sidecar"
	sidecarImage         = "ghcr.io/neuromesh-security/neuromesh-sidecar:0.1.0"
)

var (
	scheme  = runtime.NewScheme()
	decoder = serializer.NewCodecFactory(scheme).UniversalDeserializer()
)

func init() {
	_ = corev1.AddToScheme(scheme)
}

// MutateAdmissionReview handles mutating webhook requests for Pod resources.
func MutateAdmissionReview(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
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

	if req.Operation != admissionv1.Create {
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

	if hasSidecar(pod) {
		return response
	}

	patchBytes, err := buildSidecarPatch()
	if err != nil {
		response.Allowed = false
		response.Result = &metav1.Status{
			Message: fmt.Sprintf("failed to build sidecar patch: %v", err),
			Reason:  metav1.StatusReasonInternalError,
		}
		return response
	}

	patchType := admissionv1.PatchTypeJSONPatch
	response.Patch = patchBytes
	response.PatchType = &patchType
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

func hasSidecar(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name == sidecarContainerName {
			return true
		}
	}
	return false
}

func buildSidecarPatch() ([]byte, error) {
	sidecar := corev1.Container{
		Name:  sidecarContainerName,
		Image: sidecarImage,
		Args:  []string{"--mode=observe"},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: boolPtr(false),
			RunAsNonRoot:             boolPtr(true),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
	}

	patch := []map[string]interface{}{
		{
			"op":    "add",
			"path":  "/spec/containers/-",
			"value": sidecar,
		},
	}

	return json.Marshal(patch)
}

func boolPtr(value bool) *bool {
	return &value
}
