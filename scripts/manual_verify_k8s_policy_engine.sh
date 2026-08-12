#!/usr/bin/env bash
# Manual verification checklist: Kubernetes zt-policy-engine productization.
#
# Non-destructive checks against an existing k3s/Kubernetes cluster.
# Does NOT create Secrets or apply manifests by default — documents the live
# paste-back sequence from deploy/kubernetes/README.md.
#
# Usage (droplet / Linux with kubectl context set):
#   bash scripts/manual_verify_k8s_policy_engine.sh
#   APPLY=1 bash scripts/manual_verify_k8s_policy_engine.sh   # apply PE+agent if Secrets exist
#
# Paste full script output back to the PR. Live evidence is not run from Windows.
set -euo pipefail

NS="${NEUROMESH_NAMESPACE:-neuromesh-system}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY="${APPLY:-0}"

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
info() { echo "== $* =="; }

info "preflight"
command -v kubectl >/dev/null || fail "kubectl required"
command -v curl >/dev/null || fail "curl required"
kubectl get ns "$NS" >/dev/null || fail "namespace $NS missing (create or apply neuromesh-agent.yaml NS first)"

info "required Secrets present"
for s in \
  neuromesh-policy-bundle-token \
  neuromesh-policy-bundle-signing-key \
  neuromesh-policy-bundle-pubkey \
  neuromesh-spiffe-trust-bundle \
  neuromesh-cosign-pubkey
do
  kubectl -n "$NS" get secret "$s" >/dev/null || fail "missing Secret $s (see deploy/kubernetes/README.md)"
  pass "Secret $s exists"
done

if [[ "$APPLY" == "1" ]]; then
  info "APPLY=1 — applying PE then agent"
  kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-zt-policy-engine-deployment.yaml"
  kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-zt-policy-engine-service.yaml"
  kubectl -n "$NS" rollout status deploy/neuromesh-zt-policy-engine --timeout=120s
  kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-agent-correlator-rbac.yaml"
  kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-agent.yaml"
fi

info "PE Deployment Ready"
kubectl -n "$NS" get deploy neuromesh-zt-policy-engine >/dev/null \
  || fail "Deployment neuromesh-zt-policy-engine missing — apply manifests first"
READY=$(kubectl -n "$NS" get deploy neuromesh-zt-policy-engine \
  -o jsonpath='{.status.readyReplicas}')
[[ "${READY:-0}" -ge 1 ]] || fail "PE not Ready (readyReplicas=${READY:-0})"
pass "neuromesh-zt-policy-engine Ready"

info "Service ClusterIP"
SVC=$(kubectl -n "$NS" get svc neuromesh-zt-policy-engine -o jsonpath='{.spec.clusterIP}')
[[ -n "$SVC" ]] || fail "Service neuromesh-zt-policy-engine missing"
pass "Service ClusterIP=$SVC (DNS: neuromesh-zt-policy-engine.$NS.svc.cluster.local:8080)"

info "healthz + signed policy-bundle (port-forward)"
kubectl -n "$NS" port-forward svc/neuromesh-zt-policy-engine 18080:8080 >/tmp/nm-pe-pf.log 2>&1 &
PF_PID=$!
cleanup() { kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 2
curl -sfS http://127.0.0.1:18080/healthz >/dev/null || fail "/healthz failed"
pass "/healthz OK"

TOKEN=$(kubectl -n "$NS" get secret neuromesh-policy-bundle-token \
  -o jsonpath='{.data.token}' | base64 -d)
HDRS=$(mktemp)
BODY=$(mktemp)
HTTP=$(curl -sS -D "$HDRS" -o "$BODY" -w '%{http_code}' \
  -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:18080/v1/policy-bundle)
[[ "$HTTP" == "200" ]] || fail "GET /v1/policy-bundle HTTP $HTTP"
grep -qi 'X-Neuromesh-Policy-Bundle-Signature:' "$HDRS" \
  || fail "missing X-Neuromesh-Policy-Bundle-Signature header"
pass "signed policy-bundle (HTTP 200 + signature header)"

if command -v jq >/dev/null; then
  SV=$(jq -r '.schema_version // empty' "$BODY")
  [[ "$SV" == "3" ]] || fail "schema_version want 3 got ${SV:-empty}"
  jq -e '.not_before and .not_after' "$BODY" >/dev/null \
    || fail "missing not_before/not_after (T-PB-04)"
  pass "schema_version 3 + temporal fields present"
else
  grep -q '"schema_version"[[:space:]]*:[[:space:]]*3' "$BODY" \
    || fail "schema_version 3 not found (install jq for stricter check)"
  pass "schema_version 3 present (grep)"
fi

info "agent DaemonSet env wiring"
if kubectl -n "$NS" get ds neuromesh-agent >/dev/null 2>&1; then
  POD=$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=neuromesh-agent \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [[ -n "${POD:-}" ]]; then
    ENV_DUMP=$(kubectl -n "$NS" exec "$POD" -- env 2>/dev/null || true)
    echo "$ENV_DUMP" | grep -q 'NEUROMESH_ZT_POLICY_ENGINE_URL=' \
      || fail "agent missing NEUROMESH_ZT_POLICY_ENGINE_URL"
    echo "$ENV_DUMP" | grep -q 'NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH=' \
      || fail "agent missing NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH"
    pass "agent env URL + dedicated verify pubkey present"
    echo "--- recent agent logs (grep) ---"
    kubectl -n "$NS" logs "$POD" --tail=100 2>/dev/null \
      | grep -E 'applied path-prefix|policy-bundle|zt-policy-engine|schema|bundle_' || true
  else
    echo "NOTE: DaemonSet exists but no Running pod yet — skip log check"
  fi
else
  echo "NOTE: neuromesh-agent DaemonSet not applied yet (safe for deny-only until PE sync)"
fi

info "summary"
echo "PASS_COUNT=$PASS_COUNT"
echo "Install order reminder: Secrets → PE Deploy+Service → wait Ready → agent RBAC → agent DaemonSet"
echo "SPIFFE: neuromesh-spiffe-trust-bundle is mandatory (static_file); never INSECURE_MOCK_IDENTITY in cluster"
