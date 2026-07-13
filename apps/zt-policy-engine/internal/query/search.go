package query

import (
	"encoding/json"
	"net/http"
	"strings"
)

const searchTelemetryPath = "/neuromesh.policy.v1.QueryService/SearchTelemetry"

type searchRequest struct {
	Resource         string         `json:"resource"`
	Filters          []searchFilter `json:"filters"`
	Limit            int            `json:"limit"`
	LookbackMinutes  int            `json:"lookback_minutes"`
}

type searchFilter struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type searchEvent struct {
	EventID      string  `json:"eventId"`
	TimestampNs  int64   `json:"timestampNs"`
	NodeName     string  `json:"nodeName"`
	Identity     string  `json:"identity,omitempty"`
	Syscall      string  `json:"syscall,omitempty"`
	BinaryPath   string  `json:"binaryPath,omitempty"`
	Verdict      string  `json:"verdict,omitempty"`
	SourceIP     string  `json:"sourceIp,omitempty"`
	Destination  string  `json:"destinationIp,omitempty"`
	RuleID       string  `json:"ruleId,omitempty"`
	GnnScore     float64 `json:"gnnScore,omitempty"`
	Namespace    string  `json:"namespace,omitempty"`
	ResourceKind string  `json:"resourceKind,omitempty"`
}

type searchResponse struct {
	Events     []searchEvent `json:"events"`
	Total      int           `json:"total"`
	Truncated  bool          `json:"truncated"`
}

// RegisterRoutes wires the gRPC-web compatible JSON query surface.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST "+searchTelemetryPath, searchTelemetryHandler)
	mux.HandleFunc("OPTIONS "+searchTelemetryPath, optionsHandler)
}

func optionsHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func searchTelemetryHandler(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	if !isSupportedContentType(contentType) {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	var req searchRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Limit <= 0 {
		req.Limit = 250
	}
	if req.Limit > 5000 {
		req.Limit = 5000
	}

	events := filterEvents(seedEvents(), req)
	total := len(events)
	truncated := total > req.Limit
	if truncated {
		events = events[:req.Limit]
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(searchResponse{
		Events:    events,
		Total:     total,
		Truncated: truncated,
	}); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func isSupportedContentType(contentType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(contentType))
	return normalized == "" ||
		strings.HasPrefix(normalized, "application/json") ||
		strings.HasPrefix(normalized, "application/grpc-web+json") ||
		strings.HasPrefix(normalized, "application/grpc-web+proto")
}

func filterEvents(events []searchEvent, req searchRequest) []searchEvent {
	filtered := make([]searchEvent, 0, len(events))
	for _, event := range events {
		if matchesResource(event, req.Resource) && matchesFilters(event, req.Filters) {
			filtered = append(filtered, event)
		}
	}

	return filtered
}

func matchesResource(event searchEvent, resource string) bool {
	switch strings.ToLower(resource) {
	case "process":
		return event.Syscall != ""
	case "network":
		return event.SourceIP != "" || event.Destination != ""
	case "identity":
		return event.Identity != ""
	default:
		return true
	}
}

func matchesFilters(event searchEvent, filters []searchFilter) bool {
	for _, filter := range filters {
		if filter.Operator != "" && filter.Operator != "eq" {
			return false
		}

		switch filter.Field {
		case "identity":
			if event.Identity != filter.Value {
				return false
			}
		case "syscall":
			if event.Syscall != filter.Value {
				return false
			}
		case "node":
			if event.NodeName != filter.Value {
				return false
			}
		case "binary":
			if event.BinaryPath != filter.Value {
				return false
			}
		case "verdict":
			if event.Verdict != filter.Value {
				return false
			}
		case "source_ip":
			if event.SourceIP != filter.Value {
				return false
			}
		case "dest_ip":
			if event.Destination != filter.Value {
				return false
			}
		default:
			return false
		}
	}

	return true
}

func seedEvents() []searchEvent {
	return []searchEvent{
		{
			EventID:     "evt-001",
			TimestampNs: 1_750_000_000_000_000_000,
			NodeName:    "node-a",
			Identity:    "spiffe://neuromesh/agent",
			Syscall:     "execve",
			BinaryPath:  "/usr/bin/curl",
			Verdict:     "block",
		},
		{
			EventID:     "evt-002",
			TimestampNs: 1_750_000_000_100_000_000,
			NodeName:    "node-b",
			Identity:    "spiffe://neuromesh/sensor",
			Syscall:     "connect",
			BinaryPath:  "/usr/bin/ssh",
			Verdict:     "allow",
		},
		{
			EventID:     "evt-003",
			TimestampNs: 1_750_000_000_200_000_000,
			NodeName:    "node-c",
			SourceIP:    "10.0.0.4",
			Destination: "10.0.0.12",
			Verdict:     "block",
		},
		{
			EventID:      "sim-t1204-bash-exec",
			TimestampNs:  1_780_000_000_000_000_000,
			NodeName:     "neuromesh-dev",
			Namespace:    "neuromesh-dev",
			ResourceKind: "Pod",
			Identity:     "spiffe://neuromesh/agent",
			Syscall:      "execve",
			BinaryPath:   "/tmp/neuromesh-lateral-payload.sh",
			Verdict:      "block",
			RuleID:       "NEUROMESH-EXEC-BLACKLIST-PATH",
		},
		{
			EventID:      "sim-t1071-curl-exfil",
			TimestampNs:  1_780_000_000_100_000_000,
			NodeName:     "neuromesh-dev",
			Namespace:    "neuromesh-dev",
			ResourceKind: "Pod",
			Identity:     "spiffe://neuromesh/agent",
			Syscall:      "connect",
			BinaryPath:   "/usr/bin/curl",
			Verdict:      "block",
			SourceIP:     "10.42.0.12",
			Destination:  "203.0.113.50",
			RuleID:       "NEUROMESH-NET-UNKNOWN-EGRESS",
		},
		{
			EventID:      "sim-t1059-burst-4400-4505",
			TimestampNs:  1_780_000_000_200_000_000,
			NodeName:     "neuromesh-dev",
			Namespace:    "neuromesh-dev",
			ResourceKind: "Pod",
			Identity:     "spiffe://neuromesh/agent",
			Syscall:      "execve",
			BinaryPath:   "/bin/bash",
			Verdict:      "block",
			RuleID:       "NEUROMESH-EXEC-SPAWN-BURST",
			GnnScore:     0.50,
		},
		{
			EventID:      "sim-t1059-burst-4400-4506",
			TimestampNs:  1_780_000_000_300_000_000,
			NodeName:     "neuromesh-dev",
			Namespace:    "neuromesh-dev",
			ResourceKind: "Pod",
			Identity:     "spiffe://neuromesh/agent",
			Syscall:      "execve",
			BinaryPath:   "/bin/bash",
			Verdict:      "block",
			RuleID:       "NEUROMESH-EXEC-SPAWN-BURST",
			GnnScore:     0.60,
		},
		{
			EventID:      "sim-t1059-burst-4400-4507",
			TimestampNs:  1_780_000_000_400_000_000,
			NodeName:     "neuromesh-dev",
			Namespace:    "neuromesh-dev",
			ResourceKind: "Pod",
			Identity:     "spiffe://neuromesh/agent",
			Syscall:      "execve",
			BinaryPath:   "/bin/bash",
			Verdict:      "block",
			RuleID:       "NEUROMESH-EXEC-SPAWN-BURST",
			GnnScore:     0.70,
		},
		{
			EventID:      "sim-t1059-burst-4400-4508",
			TimestampNs:  1_780_000_000_500_000_000,
			NodeName:     "neuromesh-dev",
			Namespace:    "neuromesh-dev",
			ResourceKind: "Pod",
			Identity:     "spiffe://neuromesh/agent",
			Syscall:      "execve",
			BinaryPath:   "/bin/bash",
			Verdict:      "block",
			RuleID:       "NEUROMESH-EXEC-SPAWN-BURST",
			GnnScore:     0.80,
		},
		{
			EventID:      "sim-t1059-burst-4400-4509",
			TimestampNs:  1_780_000_000_600_000_000,
			NodeName:     "neuromesh-dev",
			Namespace:    "neuromesh-dev",
			ResourceKind: "Pod",
			Identity:     "spiffe://neuromesh/agent",
			Syscall:      "execve",
			BinaryPath:   "/bin/bash",
			Verdict:      "deny",
			RuleID:       "NEUROMESH-EXEC-SPAWN-BURST",
			GnnScore:     0.90,
		},
	}
}
