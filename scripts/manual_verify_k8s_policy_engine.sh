#!/usr/bin/env bash
# Mandatory live verification: Kubernetes zt-policy-engine productization (Issue #112).
#
# FULL bootstrap — Secrets, PE (fresh GHCR digest with #108 signing + #111 temporal),
# healthz + signed schema-3 bundle, agent DaemonSet wiring + sync evidence.
# This is the paste-back path (not optional). Run on the k3s droplet as root/sudo
# with kubectl configured for the cluster.
#
# Confirmed-fresh PE image (main CI after #111 merge, SHA 62062bbd…):
#   ghcr.io/neuromesh-security/neuromesh-zt-policy-engine@sha256:eceb694cc12409a935ca3d83a9ac856b0f3e4461131c63b193142aa828572255
# Do NOT use :0.1.0 — CI never publishes that tag for PE.
#
# Cosign bytecode trust root (DO NOT confuse with lab keys):
#   GHCR agent images (this script's default digest) are sign-blob'd in CI with
#   GitHub Actions secret COSIGN_PRIVATE_KEY. The MATCHING public key is
#   secrets.COSIGN_PUBLIC_KEY — NOT committed historically; extracted from the
#   Cosign/Rekor .sig bundle on this pinned image and stored at
#   deploy/kubernetes/ci-cosign.pub (ECDSA P-256).
#   ~/neuromesh-attest-lab/cosign/cosign.pub is a DIFFERENT key used only for
#   locally-built binaries. Feeding it to a GHCR image is CORRECT fail-closed
#   ("ECDSA P-256 verification failed: signature error") — wrong trust root.
#
# Usage:
#   cd /path/to/neuromesh   # checkout feat/k8s-zt-policy-engine-productize (or main with manifests)
#   # Cosign pubkey defaults to deploy/kubernetes/ci-cosign.pub (CI key).
#   # Do NOT export NEUROMESH_COSIGN_PUB_FILE to the lab attest key.
#   # Optional: real SPIFFE trust PEM (else script generates a LAB-ONLY self-signed CA for PE boot)
#   export NEUROMESH_SPIFFE_BUNDLE_PEM=/path/to/spiffe-trust-bundle.pem
#   sudo -E bash scripts/manual_verify_k8s_policy_engine.sh
#
# Paste the full script stdout/stderr back to PR #113.
set -euo pipefail

NS="${NEUROMESH_NAMESPACE:-neuromesh-system}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="${NEUROMESH_K8S_KEY_DIR:-/tmp/neuromesh-k8s-keys}"
PF_LOCAL_PORT="${NEUROMESH_PE_PF_PORT:-18080}"

# FRESH image after #109 (Issue #108 signing) + #111 (T-PB-04 temporal) — main CI 31609003980.
PE_IMAGE_DEFAULT="ghcr.io/neuromesh-security/neuromesh-zt-policy-engine@sha256:eceb694cc12409a935ca3d83a9ac856b0f3e4461131c63b193142aa828572255"
PE_IMAGE="${NEUROMESH_PE_IMAGE:-$PE_IMAGE_DEFAULT}"

# Agent image from the same main publish wave (CI name is neuromesh-agent-ebpf-sensor).
AGENT_IMAGE_DEFAULT="ghcr.io/neuromesh-security/neuromesh-agent-ebpf-sensor@sha256:413424ce5ec990e97b58014daa05ae8addab27de5afcac74904eb28fdcd5de2d"
AGENT_IMAGE="${NEUROMESH_AGENT_IMAGE:-$AGENT_IMAGE_DEFAULT}"

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
info() { echo; echo "== $* =="; }

PF_PID=""
cleanup() {
  if [[ -n "${PF_PID:-}" ]]; then
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

info "0) preflight"
command -v kubectl >/dev/null || fail "kubectl required"
command -v curl >/dev/null || fail "curl required"
command -v openssl >/dev/null || fail "openssl required"
command -v base64 >/dev/null || fail "base64 required"
test -d "$ROOT/deploy/kubernetes" || fail "repo root missing deploy/kubernetes (ROOT=$ROOT)"
echo "ROOT=$ROOT"
echo "PE_IMAGE=$PE_IMAGE"
echo "AGENT_IMAGE=$AGENT_IMAGE"

# Default: CI static Cosign public key that verifies GHCR-published agent
# bytecode-manifest.sig (same keypair as image `cosign sign` on main).
CI_COSIGN_PUB="$ROOT/deploy/kubernetes/ci-cosign.pub"
COSIGN_PUB="${NEUROMESH_COSIGN_PUB_FILE:-$CI_COSIGN_PUB}"
case "$COSIGN_PUB" in
  *neuromesh-attest-lab*|"$HOME/cosign.pub"|"$HOME/neuromesh-attest-lab/cosign/cosign.pub")
    fail "refusing lab Cosign key at $COSIGN_PUB — GHCR images need deploy/kubernetes/ci-cosign.pub (CI COSIGN_PUBLIC_KEY), not the local attest-lab key"
    ;;
esac
[[ -s "$COSIGN_PUB" ]] \
  || fail "Cosign public key missing at $COSIGN_PUB (expected deploy/kubernetes/ci-cosign.pub for GHCR images)"
echo "COSIGN_PUB=$COSIGN_PUB (CI GHCR bytecode/image trust root — not lab)"

kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS"
pass "namespace $NS ready"

info "1) generate Ed25519 policy-bundle signing keypair"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
openssl genpkey -algorithm Ed25519 -out "$KEY_DIR/policy-bundle-signing.pem"
openssl pkey -in "$KEY_DIR/policy-bundle-signing.pem" -pubout -out "$KEY_DIR/policy-bundle.pub"
chmod 600 "$KEY_DIR/policy-bundle-signing.pem"
pass "keys in $KEY_DIR"

info "2) SPIFFE trust bundle PEM (static_file — PE refuses to boot without it)"
SPIFFE_PEM="${NEUROMESH_SPIFFE_BUNDLE_PEM:-}"
if [[ -z "$SPIFFE_PEM" || ! -s "$SPIFFE_PEM" ]]; then
  SPIFFE_PEM="$KEY_DIR/spiffe-lab-ca.pem"
  echo "NOTE: generating LAB-ONLY self-signed CA at $SPIFFE_PEM"
  echo "      (enough for PE boot + /v1/policy-bundle; NOT a production SPIRE trust domain)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=neuromesh.security-lab-bootstrap" \
    -keyout "$KEY_DIR/spiffe-lab-ca.key" \
    -out "$SPIFFE_PEM" >/dev/null 2>&1
  chmod 600 "$KEY_DIR/spiffe-lab-ca.key"
fi
test -s "$SPIFFE_PEM" || fail "SPIFFE bundle PEM empty: $SPIFFE_PEM"
pass "SPIFFE bundle PEM=$SPIFFE_PEM"

info "3) create/apply Secrets (fresh token + keys every run)"
# openssl rand + new Ed25519 keypair every invocation. PE loads token and
# signing key ONCE at process start (LoadTokenFromEnv / LoadSignerFromEnv in
# cmd/server/main.go) — no file watch. Applying a new Secret without restarting
# PE leaves the old token in memory → curl 401 (seen when step 3 said
# "configured" and step 4 said Deployment unchanged).
kubectl -n "$NS" create secret generic neuromesh-policy-bundle-token \
  --from-literal=token="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
pass "Secret neuromesh-policy-bundle-token"

kubectl -n "$NS" create secret generic neuromesh-policy-bundle-signing-key \
  --from-file=signing.pem="$KEY_DIR/policy-bundle-signing.pem" \
  --dry-run=client -o yaml | kubectl apply -f -
pass "Secret neuromesh-policy-bundle-signing-key"

kubectl -n "$NS" create secret generic neuromesh-policy-bundle-pubkey \
  --from-file=bundle.pub="$KEY_DIR/policy-bundle.pub" \
  --dry-run=client -o yaml | kubectl apply -f -
pass "Secret neuromesh-policy-bundle-pubkey"

kubectl -n "$NS" create secret generic neuromesh-spiffe-trust-bundle \
  --from-file=bundle.pem="$SPIFFE_PEM" \
  --dry-run=client -o yaml | kubectl apply -f -
pass "Secret neuromesh-spiffe-trust-bundle"

kubectl -n "$NS" create secret generic neuromesh-cosign-pubkey \
  --from-file=cosign.pub="$COSIGN_PUB" \
  --dry-run=client -o yaml | kubectl apply -f -
pass "Secret neuromesh-cosign-pubkey"

info "4) apply PE Deployment + Service, pin FRESH image digest, restart for new Secrets"
kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-zt-policy-engine-deployment.yaml"
kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-zt-policy-engine-service.yaml"
kubectl -n "$NS" set image deploy/neuromesh-zt-policy-engine \
  zt-policy-engine="$PE_IMAGE"
# Spec may be unchanged from a prior run (`kubectl apply` / `set image` no-op).
# Always recycle pods so they read the Secrets just written in step 3.
kubectl -n "$NS" rollout restart deploy/neuromesh-zt-policy-engine
kubectl -n "$NS" rollout status deploy/neuromesh-zt-policy-engine --timeout=180s
READY=$(kubectl -n "$NS" get deploy neuromesh-zt-policy-engine -o jsonpath='{.status.readyReplicas}')
[[ "${READY:-0}" -ge 1 ]] || fail "PE not Ready (readyReplicas=${READY:-0}) — check: kubectl -n $NS logs deploy/neuromesh-zt-policy-engine"
pass "PE Ready with image $PE_IMAGE (restarted after Secrets)"

info "5) curl /healthz + signed GET /v1/policy-bundle"
kubectl -n "$NS" port-forward svc/neuromesh-zt-policy-engine "${PF_LOCAL_PORT}:8080" \
  >/tmp/nm-pe-pf.log 2>&1 &
PF_PID=$!
sleep 2
kill -0 "$PF_PID" 2>/dev/null || fail "port-forward failed; see /tmp/nm-pe-pf.log"

HEALTH=$(curl -sfS "http://127.0.0.1:${PF_LOCAL_PORT}/healthz") \
  || fail "curl /healthz failed"
echo "healthz body: $HEALTH"
echo "$HEALTH" | grep -q 'zt-policy-engine' || fail "unexpected /healthz body"
pass "GET /healthz OK"

TOKEN=$(kubectl -n "$NS" get secret neuromesh-policy-bundle-token \
  -o jsonpath='{.data.token}' | base64 -d)
[[ -n "$TOKEN" ]] || fail "empty policy-bundle token from Secret"

HDRS=$(mktemp)
BODY=$(mktemp)
HTTP=$(curl -sS -D "$HDRS" -o "$BODY" -w '%{http_code}' \
  -H "Authorization: Bearer ${TOKEN}" \
  "http://127.0.0.1:${PF_LOCAL_PORT}/v1/policy-bundle")
echo "---- response headers (policy-bundle) ----"
cat "$HDRS"
echo "---- response body (policy-bundle) ----"
cat "$BODY"
echo
[[ "$HTTP" == "200" ]] || fail "GET /v1/policy-bundle HTTP $HTTP (want 200)"
grep -qi '^X-Neuromesh-Policy-Bundle-Signature:' "$HDRS" \
  || fail "missing X-Neuromesh-Policy-Bundle-Signature header"
pass "GET /v1/policy-bundle HTTP 200 + signature header"

if command -v jq >/dev/null; then
  SV=$(jq -r '.schema_version // empty' "$BODY")
  [[ "$SV" == "3" ]] || fail "schema_version want 3 got ${SV:-empty}"
  jq -e '.not_before and .not_after and .deny_path_prefixes' "$BODY" >/dev/null \
    || fail "missing not_before/not_after/deny_path_prefixes"
  pass "schema_version 3 + not_before/not_after present"
else
  grep -q '"schema_version"[[:space:]]*:[[:space:]]*3' "$BODY" \
    || fail "schema_version 3 not found in body"
  grep -q 'not_before' "$BODY" && grep -q 'not_after' "$BODY" \
    || fail "not_before/not_after missing (install jq for stricter check)"
  pass "schema_version 3 + temporal fields (grep)"
fi

# Stop port-forward before agent traffic (optional; leave up if preferred)
kill "$PF_PID" 2>/dev/null || true
wait "$PF_PID" 2>/dev/null || true
PF_PID=""

info "6) apply agent RBAC + DaemonSet (pin agent image; restart for new Secrets)"
kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-agent-correlator-rbac.yaml"
kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-agent.yaml"
kubectl -n "$NS" set image ds/neuromesh-agent "agent=${AGENT_IMAGE}" || true
kubectl -n "$NS" rollout restart ds/neuromesh-agent
kubectl -n "$NS" rollout status ds/neuromesh-agent --timeout=240s || \
  echo "NOTE: DaemonSet rollout not fully Ready yet — continuing log check"

info "7) agent env + sync evidence from REAL PE (not a stub)"
POD=$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=neuromesh-agent \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[[ -n "${POD:-}" ]] || fail "no Running neuromesh-agent pod — kubectl -n $NS get pods -o wide"

# Read env from the Pod spec (API), not `kubectl exec … env` — distroless-adjacent
# images / missing `env` binary previously produced empty dumps and a false FAIL.
ENV_DUMP=$(kubectl -n "$NS" get pod "$POD" \
  -o jsonpath='{range .spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}')
echo "$ENV_DUMP" | grep -q 'NEUROMESH_ZT_POLICY_ENGINE_URL=http://neuromesh-zt-policy-engine' \
  || fail "agent missing/wrong NEUROMESH_ZT_POLICY_ENGINE_URL (spec env dump: ${ENV_DUMP:-empty})"
echo "$ENV_DUMP" | grep -q 'NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH=/etc/neuromesh/policy-bundle-pubkey/bundle.pub' \
  || fail "agent missing NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH"
echo "$ENV_DUMP" | grep -q 'NEUROMESH_POLICY_BUNDLE_TOKEN_FILE=' \
  || fail "agent missing NEUROMESH_POLICY_BUNDLE_TOKEN_FILE"
pass "agent env: PE URL + token file + dedicated verify pubkey"

echo "---- agent logs (tail, filtered) ----"
LOGS=$(kubectl -n "$NS" logs "$POD" --tail=300 2>/dev/null || true)
echo "$LOGS" | grep -E 'policy_sync|applied path-prefix|zt-policy-engine|policy-bundle|signature_|bundle_' || true
echo "$LOGS" | grep -Eq 'applied path-prefix deny list \+ identity validity|policy bundle unchanged \(identity TTL refreshed\)|path-prefix deny-list \+ identity-exception sync armed' \
  || fail "agent did not show PE sync success/armed lines — sync may still be failing (see logs above)"
pass "agent shows PE sync / apply evidence"

info "summary"
echo "PASS_COUNT=$PASS_COUNT"
echo "PE_IMAGE=$PE_IMAGE"
echo "AGENT_IMAGE=$AGENT_IMAGE"
echo "ALL PASS — paste this full output to PR #113"
