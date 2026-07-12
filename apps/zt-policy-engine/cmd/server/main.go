package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"neuromesh/zt-policy-engine/internal/evaluator"
	"neuromesh/zt-policy-engine/internal/identity"
)

type evaluateRequest struct {
	BinaryPath  string `json:"binary_path"`
	Certificate string `json:"certificate_pem,omitempty"`
	PID         uint32 `json:"pid,omitempty"`
	PPID        uint32 `json:"ppid,omitempty"`
}

type evaluateResponse struct {
	Allowed    bool   `json:"allowed"`
	DenyReason string `json:"deny_reason,omitempty"`
	Identity   string `json:"identity,omitempty"`
}

func main() {
	ctx := context.Background()

	opa, err := evaluator.NewOPAEvaluator(ctx, evaluator.DefaultExecutionPolicy)
	if err != nil {
		log.Fatalf("failed to initialize OPA evaluator: %v", err)
	}

	spiffe := identity.NewSPIFFEValidator(identity.DefaultConfig())

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"zt-policy-engine"}`))
	})
	mux.HandleFunc("POST /v1/evaluate", evaluateHandler(opa, spiffe))

	port := os.Getenv("ZT_POLICY_ENGINE_PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("zt-policy-engine listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func evaluateHandler(opa *evaluator.OPAEvaluator, spiffe *identity.SPIFFEValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req evaluateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.BinaryPath == "" {
			http.Error(w, "binary_path is required", http.StatusBadRequest)
			return
		}

		certPEM := []byte(req.Certificate)
		if len(certPEM) == 0 {
			certPEM = []byte("mock-internal")
		}

		idResult, err := spiffe.ValidateCertificatePEM(certPEM)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		decision, err := opa.Evaluate(r.Context(), evaluator.PolicyInput{
			BinaryPath: req.BinaryPath,
			Identity:   idResult.Identity.String(),
			PID:        req.PID,
			PPID:       req.PPID,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(evaluateResponse{
			Allowed:    decision.Allowed,
			DenyReason: decision.DenyReason,
			Identity:   idResult.Identity.String(),
		})
	}
}
