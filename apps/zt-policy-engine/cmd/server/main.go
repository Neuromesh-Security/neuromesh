package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"neuromesh/zt-policy-engine/internal/evaluator"
	"neuromesh/zt-policy-engine/internal/identity"
	"neuromesh/zt-policy-engine/internal/middleware"
	"neuromesh/zt-policy-engine/internal/query"
)

const (
	defaultListenPort = 8080
	maxRequestBody    = 1 << 20 // 1 MiB
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
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("POST /v1/evaluate", evaluateHandler(opa, spiffe))
	query.RegisterRoutes(mux)

	port, err := parseListenPort(os.Getenv("ZT_POLICY_ENGINE_PORT"))
	if err != nil {
		log.Fatalf("invalid listen port configuration: %v", err)
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           middleware.CORS(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		log.Println("zt-policy-engine HTTP server started")
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

func parseListenPort(raw string) (int, error) {
	if raw == "" {
		return defaultListenPort, nil
	}

	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("port must be numeric: %w", err)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}

	return port, nil
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(`{"status":"ok","service":"zt-policy-engine"}`)); err != nil {
		log.Printf("health response write failed: %v", err)
	}
}

func evaluateHandler(opa *evaluator.OPAEvaluator, spiffe *identity.SPIFFEValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

		var req evaluateRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
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
		if err := json.NewEncoder(w).Encode(evaluateResponse{
			Allowed:    decision.Allowed,
			DenyReason: decision.DenyReason,
			Identity:   idResult.Identity.String(),
		}); err != nil {
			log.Printf("evaluate response encode failed: %v", err)
		}
	}
}
