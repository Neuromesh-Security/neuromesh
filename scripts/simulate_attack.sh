#!/usr/bin/env bash
# Neuromesh Attack Simulation — safe local proof-of-value for MITRE ATT&CK T1059 / T1204.
# Triggers RuleEngine (ephemeral staging path) and DataNormalizer (spawn burst) alerts.
#
# Prerequisites:
#   - Linux host with Neuromesh orchestrator running (root / CAP_BPF)
#   - Kernel >= 5.8 with eBPF RingBuf + LSM support
#
# Usage:
#   chmod +x scripts/simulate_attack.sh
#   ./scripts/simulate_attack.sh

set -euo pipefail

readonly PAYLOAD="/tmp/neuromesh-mock-payload.sh"
readonly BURST_COUNT=10
readonly BURST_PARENT_TAG="neuromesh-burst"

log() {
    printf '[simulate-attack] %s\n' "$*"
}

require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log "ERROR: Attack simulation requires Linux (eBPF sensor is Linux-only)."
        exit 1
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
