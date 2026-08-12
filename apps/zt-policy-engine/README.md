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
    ├─► (1) Bearer token check — TRANSPORT AUTH (Issue #55)
    │         Authorization: Bearer <token>
    │
    ├─► (2) Cosign-compatible detached SIGN of exact response body
    │         — CONTENT INTEGRITY (Issue #108 / external review P0)
    │         Header: X-Neuromesh-Policy-Bundle-Signature
    │
    └─► (3) schema_version 3 body includes not_before / not_after (RFC3339)
              — ANTI-REPLAY TEMPORAL BINDING (T-PB-04)
              Inside signed bytes; agent verifies AFTER signature, BEFORE
              apply_deny_entries / apply_identity_validity (fail-closed)

    Three independent controls. Bearer alone is NOT content integrity.
    Signature alone is NOT freshness. PE refuses to boot without
    NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH.
```

### Operator note — agent sync (Phase 1)

When `NEUROMESH_ZT_POLICY_ENGINE_URL` is set on the agent (e.g. `http://zt-policy-engine:8080`),
`agent-ebpf-sensor` polls `GET /v1/policy-bundle` every **30s** with **both**:

1. **Transport auth** — shared Bearer (`NEUROMESH_POLICY_BUNDLE_TOKEN` / `_FILE`)
2. **Content integrity** — Cosign `verify-blob` over exact body bytes using
   `NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH` (fallback:
   `NEUROMESH_COSIGN_PUBLIC_KEY_PATH`, default `/etc/neuromesh/cosign/cosign.pub`)
3. **Temporal binding (T-PB-04)** — schema_version **3** `not_before` / `not_after`
   (default window **300s** = 10 × sync interval; PE override
   `NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS`; agent skew ±**5s** via
   `NEUROMESH_POLICY_BUNDLE_CLOCK_SKEW_SECS`). Rejects `bundle_expired` /
   `bundle_not_yet_valid` / `bundle_temporal_missing` before any map apply.

Missing/invalid signature or temporal failure is a sync failure: last-known-good
deny maps are retained; enforcement is never disabled (STALE after 5 minutes).
Auth rejection behaves the same. If the URL is unset, the agent uses bootstrap
defaults only (`/tmp/`, `/dev/shm/`, `/var/tmp/`). Full threat-model write-up:
`docs/threat-model.md` §4.5.

**Why 300s?** Each GET gets fresh PE timestamps (RTT+skew would suffice ideally),
but agents can be delayed (CPU/BPF). Aligning with `POLICY_STALE_AFTER` (5 min)
gives one coherent freshness horizon — short enough to bound replay of a
captured signed body, long enough that normal 30s sync never spuriously fails.

```bash
curl -s -D - -H "Authorization: Bearer $NEUROMESH_POLICY_BUNDLE_TOKEN" \
  http://localhost:8080/v1/policy-bundle | tee /dev/stderr | jq .
# Expect header: X-Neuromesh-Policy-Bundle-Signature: <base64>
```

## Policy (Sprint)

`internal/evaluator/policies/execution.rego` denies execution from ephemeral
staging prefixes `/tmp/`, `/dev/shm/`, and `/var/tmp/`. A SPIFFE whitelist
exception exists **only** for `/tmp/`; `/dev/shm/` and `/var/tmp/` are
hard-denied for every identity (matches the kernel LSM lock).

**Important:** `POST /v1/evaluate` is a **control-plane advisory** API. It is
**not** consulted by the eBPF LSM on the execve hot path. Kernel enforcement
uses `PATH_DENY_LIST` synced from `GET /v1/policy-bundle` (or bootstrap
defaults). Do not treat `/v1/evaluate` as the enforcement source of truth.

## Quickstart

**Mandatory (fail-closed):** PE will **not start** without a policy-bundle signing
key. Missing or unreadable `NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH` → process
fatal (`policy-bundle signing misconfigured`). Same class as the Issue #55 bearer
token requirement — there is no unsigned serve path.

```bash
cd apps/zt-policy-engine
go test ./...
go build -o bin/zt-policy-engine ./cmd/server

# --- Local/dev: generate an Ed25519 PKCS#8 signing key (Cosign-compatible wire) ---
# Prefer openssl 3.x. Keep the private key 0600; distribute only the .pub to agents.
mkdir -p /tmp/neuromesh-dev-keys
openssl genpkey -algorithm Ed25519 \
  -out /tmp/neuromesh-dev-keys/policy-bundle-signing.pem
openssl pkey -in /tmp/neuromesh-dev-keys/policy-bundle-signing.pem \
  -pubout -out /tmp/neuromesh-dev-keys/policy-bundle.pub
chmod 600 /tmp/neuromesh-dev-keys/policy-bundle-signing.pem

# Production-shaped local run: static PEM trust bundle (required unless mock bypass).
export ZT_POLICY_ENGINE_PORT=8080
export NEUROMESH_SPIFFE_TRUST_DOMAIN=neuromesh.security
export NEUROMESH_SPIFFE_TRUST_BUNDLE_MODE=static_file
export NEUROMESH_SPIFFE_BUNDLE_PATH=/path/to/spiffe-trust-bundle.pem
# Issue #55: required for GET /v1/policy-bundle (prefer Secret-mounted file in prod).
export NEUROMESH_POLICY_BUNDLE_TOKEN=replace-me
# Issue #108: required — absolute path to PKCS#8 PEM (ECDSA P-256 or Ed25519).
# Without this, zt-policy-engine exits at startup (fail-closed; never serves unsigned).
export NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH=/tmp/neuromesh-dev-keys/policy-bundle-signing.pem
./bin/zt-policy-engine
```

On the agent (when sync is enabled), mount/set the matching public key:

```bash
export NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH=/tmp/neuromesh-dev-keys/policy-bundle.pub
# Or reuse Cosign pubkey path if the same keypair is intentionally shared (lab only;
# production should prefer a dedicated policy-bundle key for blast-radius isolation).
```

Live fail-closed proof (valid / corrupt / missing / tampered / capture-replay):  
[`scripts/manual_verify_policy_bundle_signature.sh`](../../scripts/manual_verify_policy_bundle_signature.sh).

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
| `NEUROMESH_POLICY_BUNDLE_TOKEN` | _(required)_ | Shared Bearer token for `GET /v1/policy-bundle` transport auth (Issue #55). Missing → PE fatal at startup. |
| `NEUROMESH_POLICY_BUNDLE_TOKEN_FILE` | — | Preferred: absolute path to token file (Kubernetes Secret mount) |
| `NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH` | _(required)_ | **Fail-closed.** Absolute PKCS#8 PEM private key (ECDSA P-256 or Ed25519). Signs exact `GET /v1/policy-bundle` body; header `X-Neuromesh-Policy-Bundle-Signature`. Missing/unreadable/unsupported → PE **refuses to boot** (Issue #108). Never serves unsigned bundles. |
| `NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS` | `300` | Whole-bundle `not_after - not_before` window (T-PB-04). Override for live short-window anti-replay tests only. |


## Current limitations (honest)

- `/v1/evaluate` is a **control-plane advisory** endpoint only — **not** the
  enforcement source of truth for execve. The eBPF LSM never calls it; agent
  sync uses authenticated `GET /v1/policy-bundle` (schema_version 3) for
  path-prefix deny maps **and** identity-allow exception metadata
  (`identity_allow_exceptions`) plus whole-bundle `not_before`/`not_after`
  (T-PB-04). Kernel exceptions apply to `/tmp/` only —
  `/dev/shm/` and `/var/tmp/` stay hard-denied. SPIFFE IDs are path-form
  (`/ns/.../sa/...`). See also root `SECURITY.md` (“Control-plane advisory vs
  kernel enforcement”).
- Slice 2a is **not production-ready** without Slice 2b (real cgroup↔pod↔SPIFFE
  correlator + pod-delete invalidation). Lab-only manual seeding via
  `NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS` must never appear in
  `deploy/kubernetes/`.
- Slice **2b-i** (Issue #92) adds invalidation plumbing (pod DELETE informer +
  cgroup teardown watch). Slice **2b-ii** (automatic correlation/insert) is still
  required before identity exceptions are production-safe.
- A PE outage past the 90s identity `expires_at` sets
  `IDENTITY_EXCEPTIONS_VALID=0` for **all** exceptions (intentional).
- `GET /v1/policy-bundle` requires **both** a shared Bearer token (Issue #55,
  transport auth) **and** a Cosign-compatible detached signature
  (`X-Neuromesh-Policy-Bundle-Signature` over exact body bytes — Issue #108,
  content integrity), plus schema_version **3** temporal fields
  (`not_before`/`not_after` — T-PB-04). PE **refuses to boot** without
  `NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH`. SPIFFE mTLS was not chosen for
  Slice 0 because this repo does not yet deploy SPIRE on nodes. Live proof:
  `scripts/manual_verify_policy_bundle_signature.sh` (includes capture→replay).
- The insecure mock bypass still exists as an explicit env opt-in for local
  testing — it is fail-open for identity by design when enabled; treat enablement
  as a security incident outside developer laptops.
