#!/usr/bin/env bash
# Live verification: Splunk HEC + Datadog Logs forwarders — FIRST end-to-end delivery proof.
#
# Closes the loop from PR #146 (splunk-hec-forwarder) and PR #149 (datadog-forwarder):
# unit/isolation tests prove crate decoupling; this script proves a real agent
# BEHAVIOR_ALERT traverses Kafka and is delivered by BOTH forwarders to platform-
# shaped HTTP intakes (mock receivers on the droplet).
#
# Scenarios (all must PASS; paste full stdout/stderr back to the PR):
#   1) MOCK RECEIVERS — local Splunk HEC + Datadog Logs API v2 stubs
#   2) REAL ALERT — agent DataNormalizer spawn-burst → BEHAVIOR_ALERT on Kafka
#   3) E2E DELIVERY — both forwarders POST; captured payloads match each schema
#   4) ISOLATION REGRESSION — forwarders consume Kafka only (no agent/LSM dep)
#   5) FAULT ISOLATION — Splunk aimed at dead endpoint; network-fail metric rises;
#      Datadog (still on mock) keeps delivering a second burst unaffected
#   6) CLEANUP — trap kills mocks, forwarders, agent, optional temp Kafka topic
#
# Usage (Linux droplet — root, CONFIG_BPF_LSM, Docker for Kafka):
#   cd /path/to/neuromesh
#   git checkout feat/issue-siem-forwarders-live-verify
#   cargo build -p agent-ebpf-sensor --features orchestrator --release
#   cargo build -p splunk-hec-forwarder -p datadog-forwarder --release
#   export AGENT_BIN=./target/release/agent-ebpf-sensor
#   sudo -E bash scripts/manual_verify_siem_forwarders.sh
#
# Optional: NEUROMESH_SIEM_SKIP_BUILD=1, NEUROMESH_SIEM_SKIP_ISOLATION=1,
#   NEUROMESH_BURST_COUNT (default 10), NEUROMESH_SIEM_TEST_ROOT.
#
# Do NOT merge until every scenario PASS on a live droplet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK_DIR="${NEUROMESH_SIEM_TEST_ROOT:-/opt/neuromesh-test/siem-forwarders-live}"
PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
SPLUNK_BIN="${NEUROMESH_SPLUNK_HEC_FORWARDER_BIN:-./target/release/splunk-hec-forwarder}"
DD_BIN="${NEUROMESH_DATADOG_FORWARDER_BIN:-./target/release/datadog-forwarder}"

KAFKA_BROKERS="${NEUROMESH_KAFKA_BROKERS:-localhost:9092}"
TEST_ID="${NEUROMESH_SIEM_TEST_ID:-siem-live-$$}"
KAFKA_TOPIC="${NEUROMESH_KAFKA_TOPIC:-neuromesh.telemetry.${TEST_ID}}"

SPLUNK_MOCK_PORT="${NEUROMESH_SIEM_SPLUNK_MOCK_PORT:-18091}"
DD_MOCK_PORT="${NEUROMESH_SIEM_DD_MOCK_PORT:-18092}"
SPLUNK_METRICS_PORT="${NEUROMESH_SPLUNK_HEC_METRICS_PORT:-19091}"
DD_METRICS_PORT="${NEUROMESH_DATADOG_METRICS_PORT:-19092}"

SPLUNK_TOKEN="${NEUROMESH_SIEM_SPLUNK_TOKEN:-siem-live-hec-token}"
DD_API_KEY="${NEUROMESH_SIEM_DD_API_KEY:-siem-live-dd-api-key}"
SPLUNK_TOKEN_FILE="${WORK_DIR}/splunk-hec.token"
DD_KEY_FILE="${WORK_DIR}/datadog-api.key"

BURST_COUNT="${NEUROMESH_BURST_COUNT:-10}"
DELIVERY_WAIT_SECS="${NEUROMESH_SIEM_DELIVERY_WAIT_SECS:-90}"
FAULT_WAIT_SECS="${NEUROMESH_SIEM_FAULT_WAIT_SECS:-120}"

AGENT_LOG="${NEUROMESH_SIEM_AGENT_LOG:-${WORK_DIR}/agent.log}"
MOCK_LOG="${WORK_DIR}/mock-receivers.log"
SPLUNK_FWD_LOG="${WORK_DIR}/splunk-forwarder.log"
DD_FWD_LOG="${WORK_DIR}/datadog-forwarder.log}"

SPLUNK_CAPTURE="${WORK_DIR}/captures/splunk"
DD_CAPTURE="${WORK_DIR}/captures/datadog"

MOCK_PY="${WORK_DIR}/siem_mock_receivers.py"
MOCK_PID=""
SPLUNK_FWD_PID=""
DD_FWD_PID=""
AGENT_PID=""
KAFKA_STARTED=0
CLEANUP_DONE=0

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
info() { echo; echo "== $* =="; }

prom_counter() {
  local url="$1" name="$2" reason="${3:-}"
  curl -fsS "$url" 2>/dev/null | awk -v n="$name" -v r="$reason" '
    BEGIN { val = "" }
    $1 ~ "^"n"\\{" {
      if (r != "" && $1 !~ "reason=\""r"\"") next
      if (r == "" && $1 ~ /reason=/) next
      gsub(/ /, "", $2)
      val = $2
      exit
    }
    $1 == n {
      gsub(/ /, "", $2)
      val = $2
      exit
    }
    END {
      if (val == "") print "0"
      else print val
    }
  '
}

wait_counter_gt() {
  local url="$1" name="$2" reason="$3" baseline="$4" deadline=$((SECONDS + $5))
  while (( SECONDS < deadline )); do
    local now
    now="$(prom_counter "$url" "$name" "$reason")"
    if awk -v n="$now" -v b="$baseline" 'BEGIN { exit (n+0 > b+0) ? 0 : 1 }'; then
      echo "$now"
      return 0
    fi
    sleep 1
  done
  return 1
}

trigger_spawn_burst() {
  local tag="${1:-neuromesh-siem-burst}"
  info "triggering real spawn burst (count=${BURST_COUNT}, tag=${tag})"
  (
    export NEUROMESH_BURST_TAG="$tag"
    for _ in $(seq 1 "${BURST_COUNT}"); do
      /bin/sh -c '/usr/bin/true' >/dev/null
    done
  ) &
  wait
}

wait_agent_behavior_alert() {
  local deadline=$((SECONDS + DELIVERY_WAIT_SECS))
  while (( SECONDS < deadline )); do
    if grep -q 'NEUROMESH-EXEC-SPAWN-BURST' "$AGENT_LOG" 2>/dev/null \
      && grep -q 'BEHAVIOR_ALERT' "$AGENT_LOG" 2>/dev/null; then
      return 0
    fi
    if [[ -n "${AGENT_PID:-}" ]] && ! kill -0 "$AGENT_PID" 2>/dev/null; then
      echo "---- agent log (agent died) ----" >&2
      tail -n 160 "$AGENT_LOG" >&2 || true
      return 1
    fi
    sleep 1
  done
  echo "---- agent log (timeout) ----" >&2
  tail -n 160 "$AGENT_LOG" >&2 || true
  return 1
}

wait_capture_count() {
  local dir="$1" min="$2" deadline=$((SECONDS + DELIVERY_WAIT_SECS))
  while (( SECONDS < deadline )); do
    local n
    n="$(find "$dir" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$n" -ge "$min" ]]; then
      echo "$n"
      return 0
    fi
    sleep 1
  done
  return 1
}

stop_pid() {
  local pid="${1:-}"
  local label="${2:-process}"
  [[ -z "$pid" ]] && return 0
  local step_ec=0
  if ! kill -TERM "$pid" 2>/dev/null; then
    echo "CLEANUP: WARN — kill ${label} pid=${pid} failed (may already be gone)" >&2
    step_ec=1
  fi
  if ! wait "$pid" 2>/dev/null; then
    echo "CLEANUP: WARN — wait ${label} pid=${pid} failed" >&2
    step_ec=1
  fi
  return "$step_ec"
}

cleanup() {
  # Entire cleanup path runs with errexit OFF so no single kill/docker step
  # can silently abort mid-cleanup (same class as c3513de / desired_policy).
  set +e
  local ec=$?
  local cleanup_ec=0
  if [[ "$CLEANUP_DONE" == "1" ]]; then
    return 0
  fi
  CLEANUP_DONE=1

  info "cleanup trap (exit=${ec})"
  if ! stop_pid "${AGENT_PID:-}" "agent"; then
    cleanup_ec=1
  fi
  AGENT_PID=""
  if ! stop_pid "${SPLUNK_FWD_PID:-}" "splunk-forwarder"; then
    cleanup_ec=1
  fi
  SPLUNK_FWD_PID=""
  if ! stop_pid "${DD_FWD_PID:-}" "datadog-forwarder"; then
    cleanup_ec=1
  fi
  DD_FWD_PID=""
  if ! stop_pid "${MOCK_PID:-}" "mock-receivers"; then
    cleanup_ec=1
  fi
  MOCK_PID=""

  if [[ "$KAFKA_STARTED" == "1" ]] && command -v docker >/dev/null 2>&1; then
    if ! docker compose -f "${ROOT}/docker-compose.yml" exec -T kafka \
      /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
      --delete --topic "$KAFKA_TOPIC" >/dev/null 2>&1; then
      echo "CLEANUP: WARN — kafka topic delete failed (topic=${KAFKA_TOPIC})" >&2
      cleanup_ec=1
    fi
    if ! docker compose -f "${ROOT}/docker-compose.yml" stop kafka >/dev/null 2>&1; then
      echo "CLEANUP: WARN — docker compose stop kafka failed" >&2
      cleanup_ec=1
    fi
  fi

  if [[ "$cleanup_ec" -ne 0 ]]; then
    echo "CLEANUP: completed with errors (see WARN lines above)" >&2
  fi
  if [[ "$ec" -ne 0 ]]; then
    echo "FAIL: script exited with status $ec (cleanup attempted)" >&2
  fi
  return 0
}
trap cleanup EXIT INT TERM

info "preflight"
test "$(id -u)" -eq 0 || fail "must run as root (eBPF agent + bpffs)"
uname -s | grep -qi linux || fail "Linux host required (eBPF + Kafka lab)"
command -v python3 >/dev/null || fail "python3 required for mock receivers"
command -v curl >/dev/null || fail "curl required for metrics + health checks"
command -v docker >/dev/null || fail "docker required for Kafka (docker compose)"
test -f "${ROOT}/docker-compose.yml" || fail "docker-compose.yml missing at repo root"
test -d /sys/fs/bpf || fail "/sys/fs/bpf missing"
test -f /sys/kernel/btf/vmlinux || fail "BTF missing at /sys/kernel/btf/vmlinux"
mount | grep -Eq 'type bpf|bpffs' || mount -t bpf bpf /sys/fs/bpf || true
mkdir -p "$WORK_DIR" "$SPLUNK_CAPTURE" "$DD_CAPTURE" "$PIN_ROOT"
printf '%s\n' "$SPLUNK_TOKEN" >"$SPLUNK_TOKEN_FILE"
printf '%s\n' "$DD_API_KEY" >"$DD_KEY_FILE"
test "${SPLUNK_TOKEN_FILE:0:1}" = / || fail "SPLUNK_TOKEN_FILE must be absolute"
test "${DD_KEY_FILE:0:1}" = / || fail "DD_KEY_FILE must be absolute"
pass "preflight: root, Linux, bpf, docker, work dir ${WORK_DIR}"

if [[ "${NEUROMESH_SIEM_SKIP_BUILD:-0}" != "1" ]]; then
  info "build (release forwarders + orchestrator agent)"
  cargo build -p agent-ebpf-sensor --features orchestrator --release
  cargo build -p splunk-hec-forwarder -p datadog-forwarder --release
  pass "cargo build release binaries"
else
  info "build skipped (NEUROMESH_SIEM_SKIP_BUILD=1)"
fi
test -x "$AGENT_BIN" || fail "AGENT_BIN not executable: $AGENT_BIN"
test -x "$SPLUNK_BIN" || fail "SPLUNK_BIN not executable: $SPLUNK_BIN"
test -x "$DD_BIN" || fail "DD_BIN not executable: $DD_BIN"

info "scenario 1: mock Splunk HEC + Datadog Logs API v2 receivers"
cat >"$MOCK_PY" <<'PY'
#!/usr/bin/env python3
"""Dual mock intake: Splunk HEC event collector + Datadog Logs API v2."""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SPLUNK_PORT = int(os.environ["NEUROMESH_SIEM_SPLUNK_MOCK_PORT"])
DD_PORT = int(os.environ["NEUROMESH_SIEM_DD_MOCK_PORT"])
SPLUNK_TOKEN = os.environ["NEUROMESH_SIEM_SPLUNK_TOKEN"]
DD_API_KEY = os.environ["NEUROMESH_SIEM_DD_API_KEY"]
SPLUNK_DIR = os.environ["NEUROMESH_SIEM_SPLUNK_CAPTURE"]
DD_DIR = os.environ["NEUROMESH_SIEM_DD_CAPTURE"]

os.makedirs(SPLUNK_DIR, exist_ok=True)
os.makedirs(DD_DIR, exist_ok=True)

_splunk_seq = 0
_dd_seq = 0
_splunk_lock = threading.Lock()
_dd_lock = threading.Lock()


def _next_path(directory: str, kind: str) -> str:
    global _splunk_seq, _dd_seq
    if kind == "splunk":
        with _splunk_lock:
            _splunk_seq += 1
            n = _splunk_seq
    else:
        with _dd_lock:
            _dd_seq += 1
            n = _dd_seq
    return os.path.join(directory, f"{n:04d}.json")


class SplunkHecHandler(BaseHTTPRequestHandler):
    server_version = "NeuromeshMockSplunkHec/1.0"

    def log_message(self, fmt, *args):
        print("[splunk-mock]", fmt % args)

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if auth != f"Splunk {SPLUNK_TOKEN}":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"text":"Invalid token","code":4}')
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        path = _next_path(SPLUNK_DIR, "splunk")
        with open(path, "wb") as fh:
            fh.write(body)
        # Splunk HEC success shape
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"text":"Success","code":0}')


class DatadogLogsHandler(BaseHTTPRequestHandler):
    server_version = "NeuromeshMockDatadogLogs/1.0"

    def log_message(self, fmt, *args):
        print("[datadog-mock]", fmt % args)

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/api/v2/logs":
            self.send_response(404)
            self.end_headers()
            return
        api_key = self.headers.get("DD-API-KEY", "")
        if api_key != DD_API_KEY:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"errors":["Forbidden"]}')
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        path = _next_path(DD_DIR, "datadog")
        with open(path, "wb") as fh:
            fh.write(body)
        # Datadog Logs API v2 accepts 202 Accepted
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')


def serve(handler, port: int):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"listening 127.0.0.1:{port} handler={handler.__name__}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    t1 = threading.Thread(target=serve, args=(SplunkHecHandler, SPLUNK_PORT), daemon=True)
    t2 = threading.Thread(target=serve, args=(DatadogLogsHandler, DD_PORT), daemon=True)
    t1.start()
    t2.start()
    t1.join()
PY
chmod +x "$MOCK_PY"

export NEUROMESH_SIEM_SPLUNK_MOCK_PORT="$SPLUNK_MOCK_PORT"
export NEUROMESH_SIEM_DD_MOCK_PORT="$DD_MOCK_PORT"
export NEUROMESH_SIEM_SPLUNK_TOKEN="$SPLUNK_TOKEN"
export NEUROMESH_SIEM_DD_API_KEY="$DD_API_KEY"
export NEUROMESH_SIEM_SPLUNK_CAPTURE="$SPLUNK_CAPTURE"
export NEUROMESH_SIEM_DD_CAPTURE="$DD_CAPTURE"
: >"$MOCK_LOG"
python3 "$MOCK_PY" >>"$MOCK_LOG" 2>&1 &
MOCK_PID=$!
sleep 1
kill -0 "$MOCK_PID" || { cat "$MOCK_LOG" >&2; fail "mock receivers failed to start"; }
curl -sf -o /dev/null -w '' \
  -H "Authorization: Splunk ${SPLUNK_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"time":1,"host":"probe","source":"probe","sourcetype":"probe","event":{"probe":true}}' \
  "http://127.0.0.1:${SPLUNK_MOCK_PORT}/services/collector/event" \
  || fail "Splunk mock probe POST failed"
curl -sf -o /dev/null -w '' \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"message":"probe","hostname":"probe","service":"probe","ddsource":"probe","ddtags":"probe:1"}' \
  "http://127.0.0.1:${DD_MOCK_PORT}/api/v2/logs" \
  || fail "Datadog mock probe POST failed"
pass "scenario 1: mock receivers listening (${SPLUNK_MOCK_PORT} HEC, ${DD_MOCK_PORT} Logs v2)"

info "kafka: docker compose up (topic=${KAFKA_TOPIC})"
docker compose -f "${ROOT}/docker-compose.yml" up -d kafka
KAFKA_STARTED=1
kafka_ready=0
for _ in $(seq 1 60); do
  if docker compose -f "${ROOT}/docker-compose.yml" exec -T kafka \
    /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 \
    >/dev/null 2>&1; then
    kafka_ready=1
    break
  fi
  sleep 2
done
test "$kafka_ready" -eq 1 || fail "Kafka not ready after 120s"
docker compose -f "${ROOT}/docker-compose.yml" exec -T kafka \
  /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --create --if-not-exists --topic "$KAFKA_TOPIC" --partitions 1 --replication-factor 1 \
  >/dev/null
pass "kafka ready; topic ${KAFKA_TOPIC} created"

info "start forwarders (Kafka → mock intakes)"
: >"$SPLUNK_FWD_LOG"
: >"$DD_FWD_LOG"
export NEUROMESH_KAFKA_BROKERS="$KAFKA_BROKERS"
export NEUROMESH_KAFKA_TOPIC="$KAFKA_TOPIC"
export NEUROMESH_DATADOG_KAFKA_TOPIC="$KAFKA_TOPIC"
export NEUROMESH_SPLUNK_HEC_URL="http://127.0.0.1:${SPLUNK_MOCK_PORT}/services/collector/event"
export NEUROMESH_SPLUNK_HEC_TOKEN_FILE="$SPLUNK_TOKEN_FILE"
export NEUROMESH_SPLUNK_HEC_METRICS_PORT="$SPLUNK_METRICS_PORT"
export NEUROMESH_DATADOG_LOGS_URL="http://127.0.0.1:${DD_MOCK_PORT}/api/v2/logs"
export NEUROMESH_DATADOG_API_KEY_FILE="$DD_KEY_FILE"
export NEUROMESH_DATADOG_METRICS_PORT="$DD_METRICS_PORT"
export RUST_LOG="${RUST_LOG:-info}"

"$SPLUNK_BIN" >>"$SPLUNK_FWD_LOG" 2>&1 &
SPLUNK_FWD_PID=$!
"$DD_BIN" >>"$DD_FWD_LOG" 2>&1 &
DD_FWD_PID=$!
sleep 2
kill -0 "$SPLUNK_FWD_PID" || { tail -n 80 "$SPLUNK_FWD_LOG" >&2; fail "splunk forwarder died on start"; }
kill -0 "$DD_FWD_PID" || { tail -n 80 "$DD_FWD_LOG" >&2; fail "datadog forwarder died on start"; }
curl -sf "http://127.0.0.1:${SPLUNK_METRICS_PORT}/metrics" >/dev/null \
  || fail "splunk metrics :${SPLUNK_METRICS_PORT} unreachable"
curl -sf "http://127.0.0.1:${DD_METRICS_PORT}/metrics" >/dev/null \
  || fail "datadog metrics :${DD_METRICS_PORT} unreachable"
pass "forwarders running (metrics :${SPLUNK_METRICS_PORT} / :${DD_METRICS_PORT})"

info "scenario 2: start agent + real BEHAVIOR_ALERT via spawn burst"
: >"$AGENT_LOG"
export NEUROMESH_KAFKA_BROKERS="$KAFKA_BROKERS"
export NEUROMESH_KAFKA_TOPIC="$KAFKA_TOPIC"
export NEUROMESH_NODE_NAME="${NEUROMESH_NODE_NAME:-$(hostname -s)}"
export NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT"
export NEUROMESH_INTEGRITY_EXIT_ON_FAILURE="${NEUROMESH_INTEGRITY_EXIT_ON_FAILURE:-false}"
export RUST_LOG="${RUST_LOG:-info,neuromesh=info,agent_ebpf_sensor=info}"
unset NEUROMESH_ZT_POLICY_ENGINE_URL || true

if command -v stdbuf >/dev/null 2>&1; then
  stdbuf -oL -eL "$AGENT_BIN" >>"$AGENT_LOG" 2>&1 &
else
  "$AGENT_BIN" >>"$AGENT_LOG" 2>&1 &
fi
AGENT_PID=$!

agent_ready=0
for _ in $(seq 1 90); do
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    tail -n 120 "$AGENT_LOG" >&2
    fail "agent died during startup"
  fi
  if grep -q 'Detection brain armed' "$AGENT_LOG" 2>/dev/null \
    && grep -q 'Kafka Slow Path armed' "$AGENT_LOG" 2>/dev/null; then
    agent_ready=1
    break
  fi
  sleep 1
done
test "$agent_ready" -eq 1 || {
  tail -n 120 "$AGENT_LOG" >&2
  fail "agent never armed detection brain + Kafka slow path"
}

rm -f "${SPLUNK_CAPTURE}"/*.json "${DD_CAPTURE}"/*.json 2>/dev/null || true
# Remove probe captures from scenario 1
find "$SPLUNK_CAPTURE" "$DD_CAPTURE" -name '*.json' -delete 2>/dev/null || true

trigger_spawn_burst "siem-live-burst-1"
wait_agent_behavior_alert || fail "agent never emitted BEHAVIOR_ALERT / NEUROMESH-EXEC-SPAWN-BURST"
pass "scenario 2: genuine agent BEHAVIOR_ALERT after spawn burst (not injected Kafka fixture)"

info "scenario 3: end-to-end delivery proof (both forwarders → mock intakes)"
splunk_n="$(wait_capture_count "$SPLUNK_CAPTURE" 1)" \
  || fail "Splunk mock received no payloads within ${DELIVERY_WAIT_SECS}s"
dd_n="$(wait_capture_count "$DD_CAPTURE" 1)" \
  || fail "Datadog mock received no payloads within ${DELIVERY_WAIT_SECS}s"
echo "captures: splunk=${splunk_n} datadog=${dd_n}"

latest_splunk="$(find "$SPLUNK_CAPTURE" -name '*.json' | sort | tail -n 1)"
latest_dd="$(find "$DD_CAPTURE" -name '*.json' | sort | tail -n 1)"
test -f "$latest_splunk" && test -f "$latest_dd" || fail "capture files missing"

echo "---- Splunk HEC payload (exact bytes) ----"
cat "$latest_splunk"
echo
echo "---- Datadog Logs API v2 payload (exact bytes) ----"
cat "$latest_dd"
echo

export NEUROMESH_SIEM_SPLUNK_CAPTURE_FILE="$latest_splunk"
export NEUROMESH_SIEM_DD_CAPTURE_FILE="$latest_dd"
python3 - <<'PY' || fail "payload schema validation failed"
import json, os, sys

splunk_path = os.environ["NEUROMESH_SIEM_SPLUNK_CAPTURE_FILE"]
dd_path = os.environ["NEUROMESH_SIEM_DD_CAPTURE_FILE"]

with open(splunk_path, "rb") as f:
    splunk_raw = f.read()
with open(dd_path, "rb") as f:
    dd_raw = f.read()

splunk = json.loads(splunk_raw)
dd = json.loads(dd_raw)

# Splunk HEC {time, host, source, sourcetype, event}
for key in ("time", "host", "source", "sourcetype", "event"):
    assert key in splunk, f"Splunk missing top-level {key!r}"
event = splunk["event"]
assert isinstance(event, dict), "Splunk event must be object"
assert event.get("alert_type") == "BEHAVIOR_ALERT", event
rule = event.get("rule_id") or (event.get("payload") or {}).get("rule_id")
assert rule == "NEUROMESH-EXEC-SPAWN-BURST", rule
assert event.get("schema_version") == "neuromesh.telemetry.v1", event
assert event.get("event_id"), "Splunk event.event_id required"
assert event.get("meta", {}).get("transport") == "kafka->hec", event.get("meta")

# Datadog Logs API v2 flat item shape from apps/datadog-forwarder/src/logs.rs
for key in ("message", "hostname", "service", "ddsource", "ddtags", "event_id", "alert_type", "payload"):
    assert key in dd, f"Datadog missing {key!r}"
assert dd["alert_type"] == "BEHAVIOR_ALERT", dd
assert dd.get("rule_id") == "NEUROMESH-EXEC-SPAWN-BURST", dd
assert dd.get("schema_version") == "neuromesh.telemetry.v1", dd
assert "NEUROMESH-EXEC-SPAWN-BURST" in dd["message"], dd["message"]
assert "alert_type:BEHAVIOR_ALERT" in dd["ddtags"], dd["ddtags"]

print("schema ok:",
      "splunk_event_id=", event.get("event_id"),
      "dd_event_id=", dd.get("event_id"))
PY

hec_ok="$(prom_counter "http://127.0.0.1:${SPLUNK_METRICS_PORT}/metrics" hec_forwarded_total)"
dd_ok="$(prom_counter "http://127.0.0.1:${DD_METRICS_PORT}/metrics" dd_forwarded_total)"
awk -v h="$hec_ok" -v d="$dd_ok" 'BEGIN { exit (h+0 >= 1 && d+0 >= 1) ? 0 : 1 }' \
  || fail "forwarded_total metrics not incremented (hec=${hec_ok} dd=${dd_ok})"
pass "scenario 3: both forwarders delivered real alert; schemas validated; metrics hec=${hec_ok} dd=${dd_ok}"

info "scenario 4: isolation regression (forwarders are Kafka-only consumers)"
if [[ "${NEUROMESH_SIEM_SKIP_ISOLATION:-0}" != "1" ]]; then
  cargo test -p splunk-hec-forwarder --test isolation_test
  cargo test -p datadog-forwarder --test isolation_test
  pass "cargo isolation_test suites (manifest + ISOLATION marker)"
else
  echo "SKIP: NEUROMESH_SIEM_SKIP_ISOLATION=1"
fi

python3 - <<'PY' || fail "manifest isolation grep failed"
from pathlib import Path
root = Path("apps")
for crate in ("splunk-hec-forwarder", "datadog-forwarder"):
    text = (root / crate / "Cargo.toml").read_text()
    forbidden = ["agent-ebpf-sensor", "agent_ebpf_sensor", "aya", "neuromesh-common", "lsm", "path_deny", "policy_sync"]
    for needle in forbidden:
        assert needle not in text, f"{crate} manifest mentions forbidden {needle!r}"
print("manifest isolation: no agent/eBPF/LSM deps in either forwarder crate")
PY

cat <<EOF

EXPLICIT ISOLATION STATEMENT (design regression check):
- splunk-hec-forwarder and datadog-forwarder are standalone binaries. They do NOT
  link agent-ebpf-sensor, aya, neuromesh-common, LSM, path_deny, or policy_sync.
- Runtime data path: Kafka topic partition 0 fetch → envelope parse → bounded queue
  → HTTP POST. No agent process, BPF pin, or LSM map is consulted.
- Consumer independence: each forwarder maintains its own partition fetch cursor
  (rskafka PartitionClient; not a shared Kafka consumer group). Datadog uses
  NEUROMESH_DATADOG_KAFKA_GROUP_ID only for config/logging — it never reads
  NEUROMESH_KAFKA_GROUP_ID. Splunk and Datadog deploy as separate processes.
- This live test still needs the agent to PRODUCE the alert, but forwarder
  delivery under test does not depend on agent/LSM/path_deny — only on Kafka.

EOF
pass "scenario 4: isolation regression stated + verified (Kafka-only forwarder crates)"

info "scenario 5: fault isolation — Splunk → dead endpoint; Datadog must keep delivering"
hec_fwd_before="$(prom_counter "http://127.0.0.1:${SPLUNK_METRICS_PORT}/metrics" hec_forwarded_total)"
hec_net_before="$(prom_counter "http://127.0.0.1:${SPLUNK_METRICS_PORT}/metrics" hec_forward_failed_total network)"
dd_fwd_before="$(prom_counter "http://127.0.0.1:${DD_METRICS_PORT}/metrics" dd_forwarded_total)"
dd_count_before="$(find "$DD_CAPTURE" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"

stop_pid "$SPLUNK_FWD_PID"
SPLUNK_FWD_PID=""
sleep 1

export NEUROMESH_SPLUNK_HEC_URL="http://127.0.0.1:9/unreachable/services/collector/event"
"$SPLUNK_BIN" >>"$SPLUNK_FWD_LOG" 2>&1 &
SPLUNK_FWD_PID=$!
sleep 2
kill -0 "$SPLUNK_FWD_PID" || fail "splunk forwarder (fault mode) died on start"

trigger_spawn_burst "siem-live-burst-2-fault"
wait_agent_behavior_alert || fail "second burst: agent did not emit BEHAVIOR_ALERT"

dd_count_after=""
if ! dd_count_after="$(wait_capture_count "$DD_CAPTURE" $((dd_count_before + 1)))"; then
  echo "---- datadog forwarder log ----" >&2
  tail -n 80 "$DD_FWD_LOG" >&2 || true
  fail "Datadog mock did not receive second burst while Splunk pointed at dead endpoint"
fi

dd_fwd_after="$(wait_counter_gt "http://127.0.0.1:${DD_METRICS_PORT}/metrics" dd_forwarded_total "" "$dd_fwd_before" "$FAULT_WAIT_SECS")" \
  || fail "dd_forwarded_total did not increase during fault test (before=${dd_fwd_before})"

hec_net_after="$(wait_counter_gt "http://127.0.0.1:${SPLUNK_METRICS_PORT}/metrics" hec_forward_failed_total network "$hec_net_before" "$FAULT_WAIT_SECS")" \
  || {
    echo "---- splunk forwarder log (fault) ----" >&2
    tail -n 80 "$SPLUNK_FWD_LOG" >&2 || true
    fail "hec_forward_failed_total{reason=network} did not increase with unreachable Splunk URL"
  }

hec_fwd_after="$(prom_counter "http://127.0.0.1:${SPLUNK_METRICS_PORT}/metrics" hec_forwarded_total)"
echo "fault metrics: hec_forwarded ${hec_fwd_before} -> ${hec_fwd_after};" \
     "hec_network_fail ${hec_net_before} -> ${hec_net_after};" \
     "dd_forwarded ${dd_fwd_before} -> ${dd_fwd_after};" \
     "dd_captures ${dd_count_before} -> ${dd_count_after}"

cat <<EOF

FAULT NOTE: unreachable intake increments hec_forward_failed_total{reason=network}
after retry exhaustion (not queue_full). queue_full/backpressure is proven in unit
tests (bounded mpsc::try_send). Here we prove independent consumer isolation under
a real HTTP fault: Datadog continued forwarding while Splunk accumulated network
failures.

EOF
pass "scenario 5: Splunk network failures rose; Datadog delivered burst #2 unaffected"

info "scenario 6: cleanup (trap will also run on interruption)"
pass "scenario 6: cleanup registered via EXIT/INT/TERM trap (forwarders, mocks, agent, kafka topic)"

echo
echo "=============================================="
echo "ALL SCENARIOS PASS (${PASS_COUNT} checks)"
echo "Paste this full output + capture paths back to the PR."
echo "  Splunk capture dir: ${SPLUNK_CAPTURE}"
echo "  Datadog capture dir: ${DD_CAPTURE}"
echo "  Agent log: ${AGENT_LOG}"
echo "=============================================="
