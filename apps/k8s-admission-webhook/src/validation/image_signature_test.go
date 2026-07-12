package validation

import (
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestValidateAdmissionReview_RejectsUnsignedPod(t *testing.T) {
	t.Parallel()

	pod := corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}

	resp := ValidateAdmissionReview(&admissionv1.AdmissionRequest{
		UID:       "uid-1",
		Kind:      metav1.GroupVersionKind{Kind: "Pod"},
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	})

	if resp.Allowed {
		t.Fatal("expected unsigned pod to be rejected")
	}
}

func TestValidateAdmissionReview_AllowsSignedPod(t *testing.T) {
	t.Parallel()

	pod := corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "demo",
			Namespace:   "default",
			Annotations: map[string]string{SignedAnnotation: "true"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}

	resp := ValidateAdmissionReview(&admissionv1.AdmissionRequest{
		UID:       "uid-2",
		Kind:      metav1.GroupVersionKind{Kind: "Pod"},
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	})

	if !resp.Allowed {
		t.Fatalf("expected signed pod to be allowed: %s", resp.Result.Message)
	}
}
