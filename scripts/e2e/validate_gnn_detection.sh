#!/usr/bin/env bash
# E2E: docker compose + attack simulation + zt-policy-engine GNN insight probe.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
readonly TIMEOUT_SECS="${NEUROMESH_E2E_TIMEOUT_SECS:-30}"
readonly BOOT_TIMEOUT_SECS="${NEUROMESH_E2E_BOOT_TIMEOUT_SECS:-180}"
readonly POLICY_URL="${POLICY_URL:-http://localhost:8080}"
readonly QUERY_PATH="/neuromesh.policy.v1.QueryService/SearchTelemetry"
readonly MIN_GNN_SCORE="${NEUROMESH_MIN_GNN_SCORE:-0.8}"

log() {
  printf '[e2e-detection] %s\n' "$*"
}

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_http() {
  local url="$1"
  local label="$2"
  local timeout_secs="${3:-${BOOT_TIMEOUT_SECS}}"
  local deadline=$((SECONDS + timeout_secs))

  while ((SECONDS < deadline)); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      log "${label} is ready (${url})"
      return 0
    fi
    sleep 2
  done

  log "ERROR: timed out waiting for ${label} (${url})"
  return 1
}

wait_for_kafka() {
  local deadline=$((SECONDS + BOOT_TIMEOUT_SECS))

  while ((SECONDS < deadline)); do
    if compose exec -T kafka /opt/kafka/bin/kafka-broker-api-versions.sh \
      --bootstrap-server localhost:9092 >/dev/null 2>&1; then
      log "Kafka broker is ready"
      return 0
    fi
    sleep 3
  done

  log "ERROR: timed out waiting for Kafka broker"
  return 1
}

ensure_kafka_topic() {
  compose exec -T kafka /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create \
    --if-not-exists \
    --topic neuromesh.telemetry.v1 \
    --partitions 1 \
    --replication-factor 1 >/dev/null
  log "Kafka topic neuromesh.telemetry.v1 is ready"
}

run_attack_simulation() {
  python3 -m pip install --quiet confluent-kafka

  NEUROMESH_KAFKA_BROKERS=localhost:9092 \
    "${ROOT_DIR}/scripts/simulate_attack.sh" --kafka
}

poll_gnn_insight() {
  local payload='{"resource":"process","filters":[{"field":"identity","operator":"eq","value":"spiffe://neuromesh/agent"}],"limit":250,"lookback_minutes":240}'
  local deadline=$((SECONDS + TIMEOUT_SECS))

  while ((SECONDS < deadline)); do
    local response
    response="$(curl -fsS -X POST "${POLICY_URL}${QUERY_PATH}" \
      -H 'Content-Type: application/json' \
      -d "${payload}")"

    if printf '%s' "${response}" | python3 -c "
import json
import sys

threshold = float(sys.argv[1])
payload = json.load(sys.stdin)
for event in payload.get('events', []):
    score = event.get('gnnScore')
    if isinstance(score, (int, float)) and score > threshold:
        print(f\"matched eventId={event.get('eventId')} gnnScore={score}\")
        raise SystemExit(0)
raise SystemExit(1)
" "${MIN_GNN_SCORE}"; then
      log "GNN insight above ${MIN_GNN_SCORE} detected in control plane telemetry"
      return 0
    fi

    sleep 2
  done

  log "ERROR: no GNN insight with score > ${MIN_GNN_SCORE} within ${TIMEOUT_SECS}s"
  return 1
}

main() {
  cd "${ROOT_DIR}"

  log "Starting E2E stack (kafka, zt-policy-engine, ai-threat-detector)..."
  compose up -d --build kafka zt-policy-engine ai-threat-detector

  compose ps
  wait_for_kafka
  wait_for_http "${POLICY_URL}/healthz" "zt-policy-engine"
  ensure_kafka_topic
  run_attack_simulation
  poll_gnn_insight
}

main "$@"
