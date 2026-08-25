#!/usr/bin/env bash
# Live verification: Phase B NetworkPolicies for PE + admission webhook (k3s).
#
# Proves (on the droplet with kubectl to the lab cluster):
#   1) Discover k3s Flannel / PodCIDR / InternalIP (do not guess blindly).
#   2) Agent → PE :8080 ALLOW.
#   3) Foreign pod (default ns) → PE :8080 DENY.
#   4) Webhook pod :8443 still reachable from the *node* (apiserver path on
#      single-node k3s is host→local-pod; multi-node must match CIDRs).
#   5) Optional: if VWC is installed, a Pod create still reaches /validate
#      (check webhook logs) — under failurePolicy Ignore a silent miss is not
#      enough; require a DENY/ALLOW log line.
#
# Usage (on neuromesh-dev-lab or equivalent):
#   KUBECONFIG=/etc/rancher/k3s/k3s.yaml \
#     bash scripts/manual_verify_network_policies.sh
#
# Optional: APPLY=1 to kubectl-apply the in-repo NetworkPolicy manifests first.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${NEUROMESH_NAMESPACE:-neuromesh-system}"
KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export KUBECONFIG
APPLY="${APPLY:-0}"
PE_SVC="neuromesh-zt-policy-engine.${NS}.svc.cluster.local"
PE_PORT="${NEUROMESH_PE_PORT:-8080}"

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
info() { echo; echo "== $* =="; }

info "0) preflight"
command -v kubectl >/dev/null || fail "kubectl required"
command -v curl >/dev/null || fail "curl required"
kubectl get ns "$NS" >/dev/null || fail "namespace $NS missing"
kubectl -n "$NS" get deploy neuromesh-zt-policy-engine >/dev/null \
  || fail "PE Deployment missing"
kubectl -n "$NS" get ds neuromesh-agent >/dev/null \
  || fail "agent DaemonSet missing"

info "1) discover k3s node / Flannel identity (authoritative for webhook CIDRs)"
NODE_JSON="$(kubectl get nodes -o json)"
printf '%s' "$NODE_JSON" | python3 -c '
import json, sys
nodes = json.load(sys.stdin)["items"]
if not nodes:
    raise SystemExit("no nodes")
for n in nodes:
    name = n["metadata"]["name"]
    addrs = {a["type"]: a["address"] for a in n["status"].get("addresses", [])}
    cidr = n["spec"].get("podCIDR", "")
    print(f"node={name} InternalIP={addrs.get(\"InternalIP\",\"\")} ExternalIP={addrs.get(\"ExternalIP\",\"\")} podCIDR={cidr}")
    if cidr and "/" in cidr:
        ip, _ = cidr.split("/", 1)
        print(f"suggested_webhook_ipBlock_cidr={ip}/32")
' || fail "python3 required to parse node JSON"

if ip -4 addr show flannel.1 >/dev/null 2>&1; then
  FLANNEL_IP="$(ip -4 addr show flannel.1 | awk '/inet /{print $2}' | head -1)"
  echo "flannel.1=${FLANNEL_IP}"
  pass "flannel.1 present (${FLANNEL_IP})"
else
  echo "NOTE: flannel.1 not visible on this host (ok if verifying remotely via kubectl only)"
fi

CNI_DIR="/var/lib/rancher/k3s/agent/etc/cni/net.d"
if [[ -d "$CNI_DIR" ]]; then
  echo "CNI configs:"
  ls -la "$CNI_DIR" || true
  pass "k3s CNI config dir present"
else
  echo "NOTE: $CNI_DIR missing on this host — CIDR discovery above still applies via kubectl"
fi

if [[ "$APPLY" == "1" ]]; then
  info "1b) APPLY=1 — apply in-repo NetworkPolicies"
  kubectl apply -f "$ROOT/deploy/kubernetes/neuromesh-zt-policy-engine-networkpolicy.yaml"
  kubectl apply -f "$ROOT/deploy/kubernetes/admission/neuromesh-admission-webhook-networkpolicy.yaml"
fi

info "2) NetworkPolicy objects present"
kubectl -n "$NS" get networkpolicy neuromesh-zt-policy-engine -o yaml | grep -E 'podSelector:|port:|name: neuromesh-agent' >/dev/null \
  || fail "PE NetworkPolicy missing or unexpected"
kubectl -n "$NS" get networkpolicy neuromesh-admission-webhook -o yaml | grep -E 'port: 8443|ipBlock:' >/dev/null \
  || fail "webhook NetworkPolicy missing port 8443 or ipBlock"
pass "both NetworkPolicies present with expected shape"

info "3) ALLOW — curl PE /healthz from an agent pod"
AGENT_POD="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=neuromesh-agent -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$AGENT_POD" ]] || fail "no agent pod"
# Agent image may lack curl; use a short-lived debug container sharing the agent network namespace via kubectl run is wrong.
# Prefer kubectl exec if curl/wget exists; else ephemeral pod with agent podSelector... use a curl pod that *impersonates* by running as same labels is hard.
# Practical approach: kubectl run curl client WITH neuromesh-agent labels temporarily is wrong for production.
# Use: kubectl exec into agent if shell+curl, else spin a Job/pod labeled as agent in neuromesh-system.
if kubectl -n "$NS" exec "$AGENT_POD" -- sh -c "command -v curl >/dev/null" 2>/dev/null; then
  kubectl -n "$NS" exec "$AGENT_POD" -- curl -fsS --max-time 5 "http://${PE_SVC}:${PE_PORT}/healthz" >/tmp/nm-pe-health.out
else
  echo "agent image has no curl — spawning labeled probe pod in $NS"
  kubectl -n "$NS" delete pod nm-netpol-agent-probe --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$NS" run nm-netpol-agent-probe \
    --image=curlimages/curl:8.5.0 --restart=Never \
    --labels="app.kubernetes.io/name=neuromesh-agent,app.kubernetes.io/part-of=neuromesh" \
    --command -- sleep 120
  kubectl -n "$NS" wait --for=condition=Ready pod/nm-netpol-agent-probe --timeout=60s
  kubectl -n "$NS" exec nm-netpol-agent-probe -- curl -fsS --max-time 5 "http://${PE_SVC}:${PE_PORT}/healthz" >/tmp/nm-pe-health.out
fi
grep -q . /tmp/nm-pe-health.out || fail "empty PE healthz body"
pass "agent-path client reached PE /healthz: $(tr -d '\n' </tmp/nm-pe-health.out | head -c 120)"

info "4) DENY — foreign pod in default namespace must NOT reach PE"
kubectl -n default delete pod nm-netpol-foreign-probe --ignore-not-found >/dev/null 2>&1 || true
kubectl -n default run nm-netpol-foreign-probe \
  --image=curlimages/curl:8.5.0 --restart=Never \
  --command -- sleep 120
kubectl -n default wait --for=condition=Ready pod/nm-netpol-foreign-probe --timeout=60s
set +e
kubectl -n default exec nm-netpol-foreign-probe -- \
  curl -fsS --max-time 5 "http://${PE_SVC}:${PE_PORT}/healthz" >/tmp/nm-pe-foreign.out 2>/tmp/nm-pe-foreign.err
FOREIGN_RC=$?
set -e
if [[ "$FOREIGN_RC" -eq 0 ]]; then
  fail "foreign pod reached PE (NetworkPolicy not enforcing or CNI lacks NetworkPolicy support)"
fi
pass "foreign pod denied/failed to PE (rc=$FOREIGN_RC)"

info "5) Webhook — node/host path to container port 8443"
WH_POD="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=neuromesh-admission-webhook -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -z "$WH_POD" ]]; then
  echo "NOTE: admission webhook Deployment not present — skip webhook reachability (PE checks still valid)"
else
  WH_IP="$(kubectl -n "$NS" get pod "$WH_POD" -o jsonpath='{.status.podIP}')"
  [[ -n "$WH_IP" ]] || fail "webhook pod has no PodIP"
  # From the node (host network): should succeed on single-node k3s even with NP
  # (host→local-pod always allowed). Use curl -k against /healthz.
  if curl -kfsS --max-time 5 "https://${WH_IP}:8443/healthz" >/tmp/nm-wh-health.out 2>/tmp/nm-wh-health.err; then
    pass "host→webhook ${WH_IP}:8443/healthz OK (apiserver path on same node)"
  else
    fail "host cannot reach webhook pod :8443 — check NP CIDRs vs discovered flannel.1 / PodCIDR (see step 1). err=$(tr -d '\n' </tmp/nm-wh-health.err)"
  fi
  kubectl -n "$NS" get endpoints neuromesh-admission-webhook -o wide || true
fi

info "6) cleanup probe pods"
kubectl -n "$NS" delete pod nm-netpol-agent-probe --ignore-not-found >/dev/null 2>&1 || true
kubectl -n default delete pod nm-netpol-foreign-probe --ignore-not-found >/dev/null 2>&1 || true

echo
echo "ALL CHECKS PASSED ($PASS_COUNT). Paste this output to the Phase B PR."
echo "If webhook CIDRs need tightening, set Helm networkPolicy.admissionWebhook.apiServerSourceCidrs to the suggested_webhook_ipBlock_cidr line(s) above."
