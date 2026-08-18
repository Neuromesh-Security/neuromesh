#!/usr/bin/env bash
# Mandatory live verification for Helm-installed Neuromesh stack.
# Mirrors scripts/manual_verify_k8s_policy_engine.sh acceptance logic but
# installs resources via Helm chart phases to preserve documented order.
set -euo pipefail

NS="${NEUROMESH_NAMESPACE:-neuromesh-system}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="$ROOT/deploy/kubernetes/charts/neuromesh-security"
KEY_DIR="${NEUROMESH_K8S_KEY_DIR:-/tmp/neuromesh-k8s-keys}"
PF_LOCAL_PORT="${NEUROMESH_PE_PF_PORT:-18080}"
RELEASE="${NEUROMESH_HELM_RELEASE:-neuromesh-security}"

PE_IMAGE_DEFAULT="ghcr.io/neuromesh-security/neuromesh-zt-policy-engine@sha256:eceb694cc12409a935ca3d83a9ac856b0f3e4461131c63b193142aa828572255"
PE_IMAGE="${NEUROMESH_PE_IMAGE:-$PE_IMAGE_DEFAULT}"
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
command -v helm >/dev/null || fail "helm required"
test -d "$CHART" || fail "chart path missing: $CHART"

kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS"
pass "namespace $NS ready"

info "1) generate policy-bundle signing keypair + SPIFFE lab bundle"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
openssl genpkey -algorithm Ed25519 -out "$KEY_DIR/policy-bundle-signing.pem"
openssl pkey -in "$KEY_DIR/policy-bundle-signing.pem" -pubout -out "$KEY_DIR/policy-bundle.pub"
chmod 600 "$KEY_DIR/policy-bundle-signing.pem"

SPIFFE_PEM="${NEUROMESH_SPIFFE_BUNDLE_PEM:-}"
if [[ -z "$SPIFFE_PEM" || ! -s "$SPIFFE_PEM" ]]; then
  SPIFFE_PEM="$KEY_DIR/spiffe-lab-ca.pem"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=neuromesh.security-lab-bootstrap" \
    -keyout "$KEY_DIR/spiffe-lab-ca.key" \
    -out "$SPIFFE_PEM" >/dev/null 2>&1
  chmod 600 "$KEY_DIR/spiffe-lab-ca.key"
fi
test -s "$SPIFFE_PEM" || fail "SPIFFE bundle PEM empty: $SPIFFE_PEM"
pass "key material generated"

info "2) create secrets"
CI_COSIGN_PUB="$ROOT/deploy/kubernetes/ci-cosign.pub"
COSIGN_PUB="${NEUROMESH_COSIGN_PUB_FILE:-$CI_COSIGN_PUB}"
[[ -s "$COSIGN_PUB" ]] || fail "Cosign public key missing: $COSIGN_PUB"

kubectl -n "$NS" create secret generic neuromesh-policy-bundle-token \
  --from-literal=token="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic neuromesh-policy-bundle-signing-key \
  --from-file=signing.pem="$KEY_DIR/policy-bundle-signing.pem" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic neuromesh-policy-bundle-pubkey \
  --from-file=bundle.pub="$KEY_DIR/policy-bundle.pub" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic neuromesh-spiffe-trust-bundle \
  --from-file=bundle.pem="$SPIFFE_PEM" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic neuromesh-cosign-pubkey \
  --from-file=cosign.pub="$COSIGN_PUB" \
  --dry-run=client -o yaml | kubectl apply -f -
pass "required Secrets applied"

info "3) helm phase: policy engine only"
helm upgrade --install "$RELEASE" "$CHART" -n "$NS" \
  --set agent.enabled=false \
  --set admissionWebhook.enabled=false \
  --set validatingWebhook.enabled=false \
  --set-string images.policyEngine.repository="${PE_IMAGE%@*}" \
  --set-string images.policyEngine.digest="${PE_IMAGE#*@}" \
  --wait --timeout 180s
kubectl -n "$NS" rollout status deploy/neuromesh-zt-policy-engine --timeout=180s
pass "policy engine installed and Ready"

info "4) verify PE /healthz + signed policy bundle"
kubectl -n "$NS" port-forward svc/neuromesh-zt-policy-engine "${PF_LOCAL_PORT}:8080" \
  >/tmp/nm-pe-pf.log 2>&1 &
PF_PID=$!
sleep 2
kill -0 "$PF_PID" 2>/dev/null || fail "port-forward failed; see /tmp/nm-pe-pf.log"

HEALTH=$(curl -sfS "http://127.0.0.1:${PF_LOCAL_PORT}/healthz") || fail "curl /healthz failed"
echo "$HEALTH" | grep -q 'zt-policy-engine' || fail "unexpected /healthz body"

TOKEN=$(kubectl -n "$NS" get secret neuromesh-policy-bundle-token -o jsonpath='{.data.token}' | base64 -d)
[[ -n "$TOKEN" ]] || fail "empty policy-bundle token"
HDRS=$(mktemp)
BODY=$(mktemp)
HTTP=$(curl -sS -D "$HDRS" -o "$BODY" -w '%{http_code}' \
  -H "Authorization: Bearer ${TOKEN}" \
  "http://127.0.0.1:${PF_LOCAL_PORT}/v1/policy-bundle")
[[ "$HTTP" == "200" ]] || fail "GET /v1/policy-bundle HTTP $HTTP"
grep -qi '^X-Neuromesh-Policy-Bundle-Signature:' "$HDRS" || fail "missing signature header"
pass "policy bundle endpoint healthy and signed"

kill "$PF_PID" 2>/dev/null || true
wait "$PF_PID" 2>/dev/null || true
PF_PID=""

info "5) helm phase: enable agent (keep admission disabled)"
helm upgrade "$RELEASE" "$CHART" -n "$NS" \
  --set admissionWebhook.enabled=false \
  --set validatingWebhook.enabled=false \
  --set-string images.policyEngine.repository="${PE_IMAGE%@*}" \
  --set-string images.policyEngine.digest="${PE_IMAGE#*@}" \
  --set-string images.agent.repository="${AGENT_IMAGE%@*}" \
  --set-string images.agent.digest="${AGENT_IMAGE#*@}" \
  --wait --timeout 240s
kubectl -n "$NS" rollout status ds/neuromesh-agent --timeout=240s || true
pass "agent phase applied"

info "6) verify agent sync evidence"
POD=$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=neuromesh-agent \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[[ -n "${POD:-}" ]] || fail "no Running neuromesh-agent pod"
LOGS=$(kubectl -n "$NS" logs "$POD" --tail=300 2>/dev/null || true)
echo "$LOGS" | grep -Eq 'applied path-prefix deny list \+ identity validity|policy bundle unchanged \(identity TTL refreshed\)|path-prefix deny-list \+ identity-exception sync armed' \
  || fail "agent did not show PE sync success lines"
pass "agent shows policy sync evidence"

info "7) helm phase: admission deployment/service, then validating webhook"
helm upgrade "$RELEASE" "$CHART" -n "$NS" \
  --set validatingWebhook.enabled=false \
  --set-string images.policyEngine.repository="${PE_IMAGE%@*}" \
  --set-string images.policyEngine.digest="${PE_IMAGE#*@}" \
  --set-string images.agent.repository="${AGENT_IMAGE%@*}" \
  --set-string images.agent.digest="${AGENT_IMAGE#*@}" \
  --wait --timeout 240s
kubectl -n "$NS" rollout status deploy/neuromesh-admission-webhook --timeout=180s

helm upgrade "$RELEASE" "$CHART" -n "$NS" \
  --set-string images.policyEngine.repository="${PE_IMAGE%@*}" \
  --set-string images.policyEngine.digest="${PE_IMAGE#*@}" \
  --set-string images.agent.repository="${AGENT_IMAGE%@*}" \
  --set-string images.agent.digest="${AGENT_IMAGE#*@}"
pass "admission stack applied"

info "summary"
echo "PASS_COUNT=$PASS_COUNT"
echo "ALL PASS — Helm-installed stack functionally matches acceptance checks"
