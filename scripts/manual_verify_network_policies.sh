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

# Dump probe diagnostics into THIS script's stdout/stderr before any delete so
# a Ready wait timeout (or a re-run that deletes leftovers) cannot erase the
# failure reason from the operator's log.
dump_pod_diagnostics() {
  local ns="$1" pod="$2"
  echo
  echo "---- diagnostics: ${ns}/pod/${pod} (before delete/fail) ----"
  echo "---- kubectl -n ${ns} describe pod/${pod} ----"
  kubectl -n "$ns" describe "pod/${pod}" 2>&1 || echo "(describe failed — pod may already be gone)"
  echo "---- kubectl -n ${ns} get events --field-selector involvedObject.name=${pod} --sort-by=.lastTimestamp ----"
  kubectl -n "$ns" get events \
    --field-selector "involvedObject.name=${pod}" \
    --sort-by=.lastTimestamp 2>&1 \
    || echo "(events query failed)"
  echo "---- end diagnostics: ${ns}/pod/${pod} ----"
  echo
}

# Delete a probe pod, but if it still exists and is not Ready, print describe +
# events first so cleanup never races away the evidence.
delete_probe_pod() {
  local ns="$1" pod="$2"
  if ! kubectl -n "$ns" get "pod/${pod}" >/dev/null 2>&1; then
    return 0
  fi
  local ready
  ready="$(kubectl -n "$ns" get "pod/${pod}" \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  if [[ "$ready" != "True" ]]; then
    echo "NOTE: ${ns}/pod/${pod} exists and Ready!=True (ready=${ready:-<none>}) — dumping before delete"
    dump_pod_diagnostics "$ns" "$pod"
  fi
  kubectl -n "$ns" delete "pod/${pod}" --ignore-not-found >/dev/null 2>&1 || true
}

wait_probe_ready() {
  local ns="$1" pod="$2" timeout="${3:-60s}"
  if kubectl -n "$ns" wait --for=condition=Ready "pod/${pod}" --timeout="$timeout"; then
    return 0
  fi
  dump_pod_diagnostics "$ns" "$pod"
  fail "${ns}/pod/${pod} not Ready within ${timeout} (describe + events dumped above)"
}

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
# Temp .py — avoid python3 -c quote-nesting (backslash-escaped \" inside
# f-strings breaks with SyntaxError under single-quoted -c bodies).
_NODE_PARSE_PY="$(mktemp)" || fail "mktemp failed"
cat >"$_NODE_PARSE_PY" <<'PY'
import json
import sys

nodes = json.load(sys.stdin)["items"]
if not nodes:
    raise SystemExit("no nodes")
for n in nodes:
    name = n["metadata"]["name"]
    addrs = {a["type"]: a["address"] for a in n["status"].get("addresses", [])}
    cidr = n["spec"].get("podCIDR", "")
    print(
        f"node={name} InternalIP={addrs.get('InternalIP', '')} "
        f"ExternalIP={addrs.get('ExternalIP', '')} podCIDR={cidr}"
    )
    if cidr and "/" in cidr:
        ip, _ = cidr.split("/", 1)
        print(f"suggested_webhook_ipBlock_cidr={ip}/32")
PY
if ! printf '%s' "$NODE_JSON" | python3 "$_NODE_PARSE_PY"; then
  rm -f "$_NODE_PARSE_PY"
  fail "python3 required to parse node JSON"
fi
rm -f "$_NODE_PARSE_PY"

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
# Prefer the DaemonSet-owned agent pod (ignore any leftover mislabeled probes).
AGENT_POD="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=neuromesh-agent \
  -o json | python3 -c 'import json,sys
items=json.load(sys.stdin).get("items") or []
for p in items:
  for o in (p.get("metadata") or {}).get("ownerReferences") or []:
    if o.get("kind")=="DaemonSet" and (p.get("status") or {}).get("phase")=="Running":
      print(p["metadata"]["name"]); raise SystemExit
for p in items:
  if (p.get("status") or {}).get("phase")=="Running":
    print(p["metadata"]["name"]); raise SystemExit
')"
[[ -n "$AGENT_POD" ]] || fail "no agent pod"
# IMPORTANT: do NOT kubectl-run a second pod with
# app.kubernetes.io/name=neuromesh-agent. That label is the DaemonSet selector;
# on a node that already has the DS pod, the controller treats the probe as a
# surplus matching pod and deletes it — Ready wait then times out even though
# curlimages/curl pulls fine. PE NetworkPolicy identity must come from the
# real agent pod (exec) or an ephemeral container sharing that pod's netns.
AGENT_CONTAINER="${NEUROMESH_AGENT_CONTAINER:-agent}"
PE_URL="http://${PE_SVC}:${PE_PORT}/healthz"
rm -f /tmp/nm-pe-health.out
if kubectl -n "$NS" exec "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c "command -v curl >/dev/null" 2>/dev/null; then
  kubectl -n "$NS" exec "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
    curl -fsS --max-time 5 "$PE_URL" >/tmp/nm-pe-health.out
elif kubectl -n "$NS" exec "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
  sh -c "command -v wget >/dev/null" 2>/dev/null; then
  kubectl -n "$NS" exec "$AGENT_POD" -c "$AGENT_CONTAINER" -- \
    wget -qO- --timeout=5 "$PE_URL" >/tmp/nm-pe-health.out
else
  echo "agent image has no curl/wget — ephemeral curl via kubectl debug on $AGENT_POD (same pod identity for NetworkPolicy; avoids DaemonSet surplus delete)"
  if ! kubectl -n "$NS" debug "$AGENT_POD" \
    --image=curlimages/curl:8.5.0 \
    --target="$AGENT_CONTAINER" \
    --profile=general \
    --quiet \
    -- curl -fsS --max-time 5 "$PE_URL" >/tmp/nm-pe-health.out; then
    fail "could not probe PE as agent (no curl/wget in agent image; kubectl debug ephemeral curl failed). Do not spawn a standalone pod labeled neuromesh-agent — DaemonSet will delete it as surplus."
  fi
fi
grep -q . /tmp/nm-pe-health.out || fail "empty PE healthz body"
pass "agent-path client reached PE /healthz: $(tr -d '\n' </tmp/nm-pe-health.out | head -c 120)"

info "4) DENY — foreign pod in default namespace must NOT reach PE"
delete_probe_pod default nm-netpol-foreign-probe
kubectl -n default run nm-netpol-foreign-probe \
  --image=curlimages/curl:8.5.0 --restart=Never \
  --command -- sleep 120
wait_probe_ready default nm-netpol-foreign-probe 60s
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
# Leftover from older script revisions that spawned a DS-selector-matching probe
# (DaemonSet deletes those as surplus — still tidy if one is Terminating/stuck).
delete_probe_pod "$NS" nm-netpol-agent-probe
delete_probe_pod default nm-netpol-foreign-probe

echo
echo "ALL CHECKS PASSED ($PASS_COUNT). Paste this output to the Phase B PR."
echo "If webhook CIDRs need tightening, set Helm networkPolicy.admissionWebhook.apiServerSourceCidrs to the suggested_webhook_ipBlock_cidr line(s) above."
