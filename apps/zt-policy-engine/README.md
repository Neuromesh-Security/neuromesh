# Zero Trust Policy Engine

Go-based Core Control Plane for Neuromesh authorization decisions. Evaluates
execution requests against in-memory OPA/Rego policies and validates workload
identity via SPIFFE/SPIRE x509 SVIDs.

## Architecture

```
POST /v1/evaluate
    │
    ├─► SPIFFEValidator (mock → production mTLS)
    │
    └─► OPAEvaluator (in-memory Rego)
            │
            └─► allow / deny + deny_reason
```

## Policy (Sprint)

`internal/evaluator/policies/execution.rego` denies execution from `/tmp/`
unless the workload SPIFFE ID is in the internal whitelist.

## Quickstart

```bash
cd apps/zt-policy-engine
go test ./...
go build -o bin/zt-policy-engine ./cmd/server

export ZT_POLICY_ENGINE_PORT=8080
./bin/zt-policy-engine
```

### Evaluate an execution request

```bash
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"binary_path":"/tmp/evil.bin"}' | jq .
```

Whitelisted internal identity (mock SPIFFE) allows `/tmp/` staging:

```bash
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"binary_path":"/tmp/staged","certificate_pem":"mock"}' | jq .
```

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZT_POLICY_ENGINE_PORT` | `8080` | HTTP listen port |

## Sprint Limitations

- SPIFFE validation is mocked (`MockInternal: true`) — returns
  `spiffe://neuromesh.security/agent-ebpf-sensor` for all requests.
- PEM chain verification and SPIFFE bundle loading are stubbed for mTLS wiring
  in the next sprint.
