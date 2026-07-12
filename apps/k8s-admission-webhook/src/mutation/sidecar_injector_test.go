package mutation

import (
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestMutateAdmissionReview_InjectsSidecar(t *testing.T) {
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

	resp := MutateAdmissionReview(&admissionv1.AdmissionRequest{
		UID:       "uid-3",
		Kind:      metav1.GroupVersionKind{Kind: "Pod"},
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	})

	if !resp.Allowed {
		t.Fatalf("expected mutation to succeed: %s", resp.Result.Message)
	}
	if resp.PatchType == nil || *resp.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatal("expected JSONPatch response")
	}
	if len(resp.Patch) == 0 {
		t.Fatal("expected non-empty patch")
	}
}

func TestMutateAdmissionReview_SkipsExistingSidecar(t *testing.T) {
	t.Parallel()

	pod := corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: sidecarContainerName, Image: sidecarImage},
			{Name: "app", Image: "nginx"},
		}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}

	resp := MutateAdmissionReview(&admissionv1.AdmissionRequest{
		UID:       "uid-4",
		Kind:      metav1.GroupVersionKind{Kind: "Pod"},
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	})

	if !resp.Allowed || len(resp.Patch) != 0 {
		t.Fatal("expected no patch when sidecar already present")
	}
}
