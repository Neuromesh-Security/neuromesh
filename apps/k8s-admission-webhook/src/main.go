package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	admissionv1 "k8s.io/api/admission/v1"

	"neuromesh/k8s-admission-webhook/src/mutation"
	"neuromesh/k8s-admission-webhook/src/validation"
)

const (
	defaultListenAddr   = ":8443"
	defaultCertFile     = "/etc/webhook/certs/tls.crt"
	defaultKeyFile      = "/etc/webhook/certs/tls.key"
	validatePath        = "/validate"
	mutatePath          = "/mutate"
	healthPath          = "/healthz"
	admissionReviewKind = "AdmissionReview"
)

func main() {
	// Fail closed on startup if the image signature trust root cannot be
	// loaded -- serving admission traffic without a working verifier would
	// mean silently allowing unverified images, which is unacceptable for a
	// security-gating webhook.
	verifier, err := validation.NewVerifierFromEnv()
	if err != nil {
		log.Fatalf("failed to initialize container image signature verifier: %v", err)
	}
	validator := validation.NewValidator(verifier)

	mux := http.NewServeMux()
	mux.HandleFunc(healthPath, healthHandler)
	mux.HandleFunc(validatePath, admissionHandler(validator.ValidateAdmissionReview))
	mux.HandleFunc(mutatePath, admissionHandler(func(_ context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
		return mutation.MutateAdmissionReview(req)
	}))

	addr := envOrDefault("WEBHOOK_LISTEN_ADDR", defaultListenAddr)
	certFile := envOrDefault("WEBHOOK_TLS_CERT_FILE", defaultCertFile)
	keyFile := envOrDefault("WEBHOOK_TLS_KEY_FILE", defaultKeyFile)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("k8s-admission-webhook listening on %s (TLS)", addr)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("webhook server failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

type reviewHandler func(context.Context, *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse

func admissionHandler(handler reviewHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		var review admissionv1.AdmissionReview
		if err := json.Unmarshal(body, &review); err != nil {
			http.Error(w, "invalid AdmissionReview JSON", http.StatusBadRequest)
			return
		}

		if review.Request == nil {
			http.Error(w, "missing admission request", http.StatusBadRequest)
			return
		}

		review.Response = handler(r.Context(), review.Request)
		review.APIVersion = "admission.k8s.io/v1"
		review.Kind = admissionReviewKind
		review.Response.UID = review.Request.UID

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(review); err != nil {
			log.Printf("failed to encode AdmissionReview response: %v", err)
		}
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","service":"k8s-admission-webhook"}`))
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
