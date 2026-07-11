#!/usr/bin/env bash
# Neuromesh Red Team Simulation — ephemeral payload execution in blacklisted paths.
# Validates RuleEngine whitelist suppression and CRITICAL_ALERT JSON SIEM output.

set -euo pipefail

readonly PAYLOAD="/tmp/evil_payload.bin"
readonly BENIGN_COMMANDS=(
    "ls -la /var"
    "cat /etc/hostname"
)

log() {
    printf '[red-team] %s\n' "$*"
}

require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        log "ERROR: This simulation requires Linux (eBPF sensor runs on Linux)."
        exit 1
    fi
}

run_benign_noise() {
    log "Phase 1: emitting benign noise (expect RuleEngine silent suppression)..."
    for cmd in "${BENIGN_COMMANDS[@]}"; do
        log "  running: ${cmd}"
        # shellcheck disable=SC2086
        eval "${cmd}" >/dev/null
    done
    log "Benign noise complete. No CRITICAL_ALERT JSON should appear in the orchestrator terminal."
}

deploy_payload() {
    log "Phase 2: staging ephemeral payload in blacklisted directory..."
    cp /bin/true "${PAYLOAD}"
    chmod +x "${PAYLOAD}"
    log "Payload deployed at ${PAYLOAD}"
}

trigger_alert() {
    log "Phase 3: executing payload (expect CRITICAL_ALERT JSON on orchestrator stdout)..."
    "${PAYLOAD}"
    log "Payload executed. Verify orchestrator emitted JSON with severity=CRITICAL_ALERT."
}

cleanup() {
    log "Phase 4: cleaning up temporary artifacts..."
    rm -f "${PAYLOAD}"
    log "Cleanup complete."
}

main() {
    require_linux
    trap cleanup EXIT

    log "Starting Neuromesh red-team simulation..."
    run_benign_noise
    deploy_payload
    trigger_alert
    log "Simulation finished successfully."
}

main "$@"
