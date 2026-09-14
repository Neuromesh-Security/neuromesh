#!/usr/bin/env bash
# Live diagnostic: Cosign attestation wiring vs agent CrashLoop
# "Cosign public key missing at /etc/neuromesh/cosign/cosign.pub"
#
# Writes NDJSON to debug-d010bd.log (repo root or DEBUG_LOG_PATH).
# Run on the lab droplet with kubectl access. Does not modify the cluster.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${NS:-neuromesh-system}"
LOG="${DEBUG_LOG_PATH:-$ROOT/debug-d010bd.log}"
KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export KUBECONFIG
SESSION_ID="d010bd"
RUN_ID="${DEBUG_RUN_ID:-live-$(date -u +%Y%m%dT%H%M%SZ)}"

log_ndjson() {
  local hyp="$1" loc="$2" msg="$3" data="$4"
  local ts
  ts="$(date +%s)000"
  printf '{"sessionId":"%s","runId":"%s","hypothesisId":"%s","location":"%s","message":"%s","data":%s,"timestamp":%s}\n' \
    "$SESSION_ID" "$RUN_ID" "$hyp" "$loc" "$msg" "$data" "$ts" | tee -a "$LOG" >/dev/null
  echo "[$hyp] $msg $data" >&2
}

echo "Writing diagnostics to $LOG (runId=$RUN_ID)" >&2

# H1: Live DaemonSet missing cosign volumeMount / volume
DS_JSON="$(kubectl -n "$NS" get ds neuromesh-agent -o json 2>/dev/null || echo '{}')"
HAS_ENV="$(echo "$DS_JSON" | jq -r '
  [.spec.template.spec.containers[]? | select(.name=="agent") | .env[]? | select(.name=="NEUROMESH_COSIGN_PUBLIC_KEY_PATH") | .value] | first // "ABSENT"
')"
HAS_MOUNT="$(echo "$DS_JSON" | jq -r '
  [.spec.template.spec.containers[]? | select(.name=="agent") | .volumeMounts[]? | select(.name=="cosign-pubkey") | .mountPath] | first // "ABSENT"
')"
HAS_VOL="$(echo "$DS_JSON" | jq -r '
  [.spec.template.spec.volumes[]? | select(.name=="cosign-pubkey") | .secret.secretName] | first // "ABSENT"
')"
IMAGE="$(echo "$DS_JSON" | jq -r '
  [.spec.template.spec.containers[]? | select(.name=="agent") | .image] | first // "ABSENT"
')"
log_ndjson "H1" "debug_agent_cosign_wiring.sh:ds" "live DaemonSet cosign wiring" \
  "$(jq -nc --arg env "$HAS_ENV" --arg mount "$HAS_MOUNT" --arg vol "$HAS_VOL" --arg image "$IMAGE" \
    '{cosignEnv:$env,cosignMount:$mount,cosignSecretVol:$vol,image:$image}')"

# H2: Secret missing / empty / wrong key
SEC_EXISTS="false"
SEC_KEYS=""
SEC_LEN=0
if kubectl -n "$NS" get secret neuromesh-cosign-pubkey >/dev/null 2>&1; then
  SEC_EXISTS="true"
  SEC_KEYS="$(kubectl -n "$NS" get secret neuromesh-cosign-pubkey -o jsonpath='{.data}' | jq -r 'keys|join(",")')"
  SEC_B64="$(kubectl -n "$NS" get secret neuromesh-cosign-pubkey -o jsonpath='{.data.cosign\.pub}' 2>/dev/null || true)"
  if [[ -n "${SEC_B64:-}" ]]; then
    SEC_LEN="$(printf '%s' "$SEC_B64" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
  fi
fi
log_ndjson "H2" "debug_agent_cosign_wiring.sh:secret" "neuromesh-cosign-pubkey presence" \
  "$(jq -nc --arg e "$SEC_EXISTS" --arg k "$SEC_KEYS" --argjson n "${SEC_LEN:-0}" \
    '{exists:$e,keys:$k,cosignPubBytes:$n}')"

# H3: Pod phase / crash reason / recent logs (path contract unchanged in binary)
POD="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=neuromesh-agent -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -n "${POD:-}" ]]; then
  PHASE="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}')"
  WAIT="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)"
  TERM="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}' 2>/dev/null || true)"
  READY="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].ready}')"
  IMG_ID="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
  POD_MOUNTS="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{range .spec.containers[0].volumeMounts[*]}{.name}={.mountPath};{end}')"
  LOGS="$(kubectl -n "$NS" logs "$POD" --tail=40 2>&1 | tr '\n' '|' | tr '"' "'" | head -c 2000)"
  log_ndjson "H3" "debug_agent_cosign_wiring.sh:pod" "agent pod runtime state" \
    "$(jq -nc --arg pod "$POD" --arg phase "$PHASE" --arg wait "$WAIT" --arg term "$TERM" \
      --arg ready "$READY" --arg img "$IMG_ID" --arg mounts "$POD_MOUNTS" --arg logs "$LOGS" \
      '{pod:$pod,phase:$phase,waiting:$wait,terminated:$term,ready:$ready,imageID:$img,volumeMounts:$mounts,logsTail:$logs}')"
else
  log_ndjson "H3" "debug_agent_cosign_wiring.sh:pod" "no agent pod found" '{"pod":null}'
fi

# H4: Compare committed raw manifest expectations
EXPECTED_ENV="/etc/neuromesh/cosign/cosign.pub"
EXPECTED_MOUNT="/etc/neuromesh/cosign"
EXPECTED_SECRET="neuromesh-cosign-pubkey"
MATCH_ENV="false"; [[ "$HAS_ENV" == "$EXPECTED_ENV" || "$HAS_ENV" == "ABSENT" ]] && true
[[ "$HAS_ENV" == "$EXPECTED_ENV" ]] && MATCH_ENV="true"
MATCH_MOUNT="false"; [[ "$HAS_MOUNT" == "$EXPECTED_MOUNT" ]] && MATCH_MOUNT="true"
MATCH_VOL="false"; [[ "$HAS_VOL" == "$EXPECTED_SECRET" ]] && MATCH_VOL="true"
log_ndjson "H4" "debug_agent_cosign_wiring.sh:compare" "live vs committed contract" \
  "$(jq -nc --arg ee "$EXPECTED_ENV" --arg em "$EXPECTED_MOUNT" --arg es "$EXPECTED_SECRET" \
    --argjson me "$MATCH_ENV" --argjson mm "$MATCH_MOUNT" --argjson mv "$MATCH_VOL" \
    '{expectedEnv:$ee,expectedMount:$em,expectedSecret:$es,envMatches:$me,mountMatches:$mm,volMatches:$mv}')"

# H5: FailedMount events (secret present in DS but missing in API)
EVENTS="$(kubectl -n "$NS" get events --field-selector involvedObject.name=neuromesh-agent --sort-by=.lastTimestamp 2>/dev/null \
  | tail -n 15 | tr '\n' '|' | tr '"' "'" | head -c 1500)"
log_ndjson "H5" "debug_agent_cosign_wiring.sh:events" "recent DaemonSet-related events" \
  "$(jq -nc --arg e "$EVENTS" '{events:$e}')"

echo "Done. Paste or scp $LOG back for analysis." >&2
