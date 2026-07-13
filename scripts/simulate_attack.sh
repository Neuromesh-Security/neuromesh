#!/usr/bin/env bash
# Neuromesh Attack Simulation — safe local proof-of-value for MITRE ATT&CK T1059 / T1204.
# Triggers RuleEngine (ephemeral staging path) and DataNormalizer (spawn burst) alerts.
#
# Modes:
#   Linux + eBPF:  ./scripts/simulate_attack.sh
#   Kafka mock:    ./scripts/simulate_attack.sh --kafka
#                  (or: python scripts/mock_ebpf_stream.py)
#
# Prerequisites (eBPF mode):
#   - Linux host with Neuromesh orchestrator running (root / CAP_BPF)
#   - Kernel >= 5.8 with eBPF RingBuf + LSM support
#
# Prerequisites (Kafka mock mode):
#   - Kafka broker on localhost:9092
#   - pip install confluent-kafka

set -euo pipefail

readonly PAYLOAD="/tmp/neuromesh-mock-payload.sh"
readonly BURST_COUNT=10
readonly BURST_PARENT_TAG="neuromesh-burst"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
    printf '[simulate-attack] %s\n' "$*"
}

kafka_simulation() {
    log "Kafka mock mode — injecting synthetic Ring 0 telemetry..."
    if command -v python3 >/dev/null 2>&1; then
        python3 "${SCRIPT_DIR}/mock_ebpf_stream.py" --brokers "${NEUROMESH_KAFKA_BROKERS:-localhost:9092}"
    elif command -v python >/dev/null 2>&1; then
        python "${SCRIPT_DIR}/mock_ebpf_stream.py" --brokers "${NEUROMESH_KAFKA_BROKERS:-localhost:9092}"
    else
        log "ERROR: python3 required for Kafka mock mode."
        exit 1
    fi
}

require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log "Non-Linux host detected — falling back to Kafka mock injector."
        kafka_simulation
        exit 0
    fi
}

phase_benign_baseline() {
    log "Phase 1 [baseline]: benign commands (expect RuleEngine suppression)..."
    /bin/ls /etc >/dev/null
    /bin/cat /etc/hostname >/dev/null
    log "Benign baseline complete — no CRITICAL_ALERT expected."
}

phase_t1204_staging_execution() {
    log "Phase 2 [T1204]: staging mock payload in /tmp and executing..."
    cat >"${PAYLOAD}" <<'EOF'
#!/bin/sh
# Mock adversary payload — exits immediately, no network or file destruction.
echo "neuromesh-mock-payload"
EOF
    chmod +x "${PAYLOAD}"
    log "  dropped payload: ${PAYLOAD}"
    "${PAYLOAD}"
    log "T1204 simulation complete — expect CRITICAL_ALERT JSON (matched_pattern=/tmp/)."
}

phase_t1059_spawn_burst() {
    log "Phase 3 [T1059.004]: rapid shell spawn burst (expect BEHAVIOR_ALERT)..."
    log "  parent tag: ${BURST_PARENT_TAG} | burst size: ${BURST_COUNT}"

    # Subshell keeps a stable ppid for DataNormalizer parent-keyed frequency analysis.
    (
        for _ in $(seq 1 "${BURST_COUNT}"); do
            /bin/sh -c '/usr/bin/true' >/dev/null
        done
    ) &
    wait
    log "T1059 spawn burst complete — expect BEHAVIOR_ALERT JSON (rule_id=NEUROMESH-EXEC-SPAWN-BURST)."
}

cleanup() {
    log "Phase 4 [cleanup]: removing mock artifacts..."
    rm -f "${PAYLOAD}"
    log "Cleanup complete."
}

main() {
    if [[ "${1:-}" == "--kafka" ]]; then
        kafka_simulation
        exit 0
    fi

    require_linux
    trap cleanup EXIT

    log "Starting Neuromesh MITRE T1059/T1204 attack simulation..."
    log "Watch the orchestrator stdout for JSON alert lines."
    echo

    phase_benign_baseline
    echo
    phase_t1204_staging_execution
    echo
    phase_t1059_spawn_burst
    echo
    log "Simulation finished. Validate:"
    log "  - CRITICAL_ALERT from RuleEngine (blacklisted /tmp/ execution)"
    log "  - BEHAVIOR_ALERT from DataNormalizer (rapid spawn burst)"
}

main "$@"
