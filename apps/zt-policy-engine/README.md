# Zero Trust Policy Engine

Go-based Core Control Plane for Neuromesh authorization decisions. Evaluates
execution requests against in-memory OPA/Rego policies and validates workload
identity via SPIFFE/SPIRE X.509-SVIDs (real cryptographic chain verification —
not a mock-by-default control plane).

## Architecture

```
POST /v1/evaluate
    │
    ├─► SPIFFEValidator (go-spiffe/v2 chain verify vs trust bundle)
    │       └─ optional InsecureMockIdentity bypass (env opt-in ONLY)
    │
    └─► OPAEvaluator (in-memory Rego)
            │
            └─► allow / deny + deny_reason

GET /v1/policy-bundle
    │
    └─► compiled path-prefix deny list for agent BPF map sync (Phase 1)
        (no OPA / no SPIFFE on this endpoint; currently unauthenticated)
```

### Operator note — agent sync (Phase 1)

When `NEUROMESH_ZT_POLICY_ENGINE_URL` is set on the agent (e.g. `http://zt-policy-engine:8080`),
`agent-ebpf-sensor` polls `GET /v1/policy-bundle` every **30s**, writes prefixes into
BPF maps, and keeps enforcing last-known-good on failure (STALE after 5 minutes —
enforcement is never disabled). If the URL is unset, the agent uses bootstrap
defaults only (`/tmp/`, `/dev/shm/`, `/var/tmp/`). Full threat-model write-up:
`docs/threat-model.md` §4.5.

```bash
curl -s http://localhost:8080/v1/policy-bundle | jq .
```

## Policy (Sprint)

`internal/evaluator/policies/execution.rego` denies execution from `/tmp/`
unless the workload SPIFFE ID is in the internal whitelist.

## Quickstart

```bash
cd apps/zt-policy-engine
go test ./...
go build -o bin/zt-policy-engine ./cmd/server

# Production-shaped local run: static PEM trust bundle (required unless mock bypass).
export ZT_POLICY_ENGINE_PORT=8080
export NEUROMESH_SPIFFE_TRUST_DOMAIN=neuromesh.security
export NEUROMESH_SPIFFE_TRUST_BUNDLE_MODE=static_file
export NEUROMESH_SPIFFE_BUNDLE_PATH=/path/to/spiffe-trust-bundle.pem
./bin/zt-policy-engine
```

### Evaluate an execution request

A missing or malformed `certificate_pem` is **fail-closed** (HTTP 401) — there is
no synthesized fallback identity.

```bash
# No certificate → identity denial (expected)
curl -s -o /dev/stderr -w "%{http_code}\n" -X POST http://localhost:8080/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"binary_path":"/tmp/evil.bin"}'
```

Present a real leaf X.509-SVID (PEM) whose chain verifies against the configured
trust bundle. The value of `certificate_pem` must be PEM-encoded certificate
bytes (typically a leaf, optionally with intermediates), **not** the literal
string `"mock"`:

```bash
# $LEAF_PEM is a PEM file for a leaf SVID issued under your trust bundle CA
curl -s -X POST http://localhost:8080/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --rawfile cert "$LEAF_PEM" \
        '{binary_path:"/bin/ls", certificate_pem:$cert}')" | jq .
```

Whitelisted SPIFFE IDs may be allowed to stage under `/tmp/` per Rego; that
decision still requires a **cryptographically verified** identity first.

### Local-only mock bypass (insecure)

`MockInternal` no longer exists. The only bypass is
`NEUROMESH_INSECURE_MOCK_IDENTITY=true` (`InsecureMockIdentity`), which
short-circuits every validation call to a fake internal identity with **no**
cryptographic verification and emits a loud security warning. Use only for
local plumbing tests — never in shared or production environments.

```bash
export NEUROMESH_INSECURE_MOCK_IDENTITY=true
# Trust bundle mode is not required when the mock bypass is active
./bin/zt-policy-engine
```

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZT_POLICY_ENGINE_PORT` | `8080` | HTTP listen port |
| `NEUROMESH_SPIFFE_TRUST_DOMAIN` | `neuromesh.security` | Trusted SPIFFE trust domain |
| `NEUROMESH_SPIFFE_TRUST_BUNDLE_MODE` | _(required)_ | `static_file` or `workload_api` (unless mock bypass) |
| `NEUROMESH_SPIFFE_BUNDLE_PATH` | — | PEM trust bundle path (`static_file` mode) |
| `NEUROMESH_SPIFFE_WORKLOAD_API_ADDR` | — | Optional Workload API socket override |
| `NEUROMESH_SPIFFE_EXPECTED_ID_PATTERN` | — | Optional regexp on SPIFFE ID path |
| `NEUROMESH_INSECURE_MOCK_IDENTITY` | unset / false | Exact value `true` enables insecure mock bypass |

## Current limitations (honest)

- `/v1/evaluate` is **not** called from the eBPF LSM hot path. Phase 1 agent sync
  uses `GET /v1/policy-bundle` for path-prefix deny-list maps only; SPIFFE-based
  allow-exceptions for ephemeral paths remain a Phase 2 / Slow Path concern.
- `GET /v1/policy-bundle` is **unauthenticated**. Accepted for Phase 1 (exported
  prefixes are not secret); **must be authenticated before Phase 2** when the
  bundle would include SPIFFE allow-exceptions. Tracked in
  [#55](https://github.com/Neuromesh-Security/neuromesh/issues/55).
- The insecure mock bypass still exists as an explicit env opt-in for local
  testing — it is fail-open for identity by design when enabled; treat enablement
  as a security incident outside developer laptops.
