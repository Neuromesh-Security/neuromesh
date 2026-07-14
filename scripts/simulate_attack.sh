#!/usr/bin/env bash
# =============================================================================
# Neuromesh Attack Simulation — v0.1.0-core
# =============================================================================
# Safe, local proof-of-value for the eBPF Sensor Core LSM enforcement plane
# and user-space detection pipeline (RuleEngine + DataNormalizer).
#
# Simulates:
#   - MITRE T1204  User Execution (malicious file staged in ephemeral paths)
#   - MITRE T1059  Command and Scripting Interpreter (spawn burst)
#   - MITRE T1059.004 Unix Shell (rapid /bin/sh child processes)
#
# LSM enforcement (Ring 0):
#   Blocks execution from /tmp/, /dev/shm/, /var/tmp/ via bprm_check_security.
#   A blocked attempt returns non-zero exit (typically Permission denied).
#
# Modes:
#   ./scripts/simulate_attack.sh           Live Linux + running sensor
#   ./scripts/simulate_attack.sh --kafka   Synthetic Kafka telemetry (no eBPF)
#
# Prerequisites (live mode):
#   - Linux kernel >= 5.8 with CONFIG_BPF_LSM and BTF
#   - Neuromesh orchestrator running as root (see scripts/demo_core.sh)
# =============================================================================

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BURST_COUNT="${NEUROMESH_BURST_COUNT:-10}"
readonly BURST_PARENT_TAG="neuromesh-burst"

# Ephemeral staging paths enforced by neuromesh_lsm_exec_guard (LSM deny list).
readonly -a LSM_STAGING_PATHS=(
    "/tmp/neuromesh-lsm-payload.sh"
    "/dev/shm/neuromesh-lsm-payload.sh"
    "/var/tmp/neuromesh-lsm-payload.sh"
)

# ANSI colors (disabled when stdout is not a TTY).
if [[ -t 1 ]]; then
    readonly C_RESET='\033[0m'
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_YELLOW='\033[1;33m'
    readonly C_BLUE='\033[0;34m'
    readonly C_CYAN='\033[0;36m'
    readonly C_BOLD='\033[1m'
else
    readonly C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN='' C_BOLD=''
fi

# Track created artifacts for trap cleanup.
declare -a CREATED_ARTIFACTS=()

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

log_info() {
    printf '%b[simulate-attack] %s%b\n' "${C_BLUE}" "$*" "${C_RESET}"
}

log_ok() {
    printf '%b[simulate-attack] ✓ %s%b\n' "${C_GREEN}" "$*" "${C_RESET}"
}

log_warn() {
    printf '%b[simulate-attack] ⚠ %s%b\n' "${C_YELLOW}" "$*" "${C_RESET}" >&2
}

log_error() {
    printf '%b[simulate-attack] ✗ %s%b\n' "${C_RED}" "$*" "${C_RESET}" >&2
}

log_phase() {
    printf '\n%b[simulate-attack] ── %s ──%b\n' "${C_BOLD}${C_CYAN}" "$*" "${C_RESET}"
}

log_mitre() {
    printf '%b[simulate-attack]   MITRE: %s%b\n' "${C_CYAN}" "$*" "${C_RESET}"
}

die() {
    log_error "$*"
    exit 1
}

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------

require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        die "Live simulation requires Linux. Use --kafka for synthetic telemetry."
    fi
}

kafka_simulation() {
    log_info "Kafka mock mode — injecting synthetic Ring 0 telemetry..."
    local py=""
    if command -v python3 >/dev/null 2>&1; then
        py="python3"
    elif command -v python >/dev/null 2>&1; then
        py="python"
    else
        die "python3 required for --kafka mode."
    fi
    "${py}" "${SCRIPT_DIR}/mock_ebpf_stream.py" \
        --brokers "${NEUROMESH_KAFKA_BROKERS:-localhost:9092}"
}

write_payload() {
    local path="$1"
    cat >"${path}" <<'EOF'
#!/bin/sh
# Neuromesh mock adversary payload — no network, no filesystem destruction.
# If this line prints, LSM enforcement did NOT block execution.
echo "neuromesh-lsm-payload-ran"
EOF
    chmod +x "${path}"
    CREATED_ARTIFACTS+=("${path}")
}

# ---------------------------------------------------------------------------
# Phase 1 — Benign baseline (whitelist suppression)
# ---------------------------------------------------------------------------

phase_benign_baseline() {
    log_phase "Phase 1: Benign baseline"
    log_mitre "T1059 — Command and Scripting Interpreter (legitimate admin activity)"
    log_info "Executing whitelisted paths (/bin/ls, /bin/cat) — expect RuleEngine suppression."

    /bin/ls /etc >/dev/null
    /bin/cat /etc/hostname >/dev/null

    log_ok "Benign commands completed — no CRITICAL_ALERT expected on sensor stdout."
}

# ---------------------------------------------------------------------------
# Phase 2 — LSM enforcement on ephemeral staging paths (T1204)
# ---------------------------------------------------------------------------

attempt_lsm_blocked_exec() {
    local payload_path="$1"
    local staging_prefix="$2"

    log_info "Staging payload: ${payload_path}"
    write_payload "${payload_path}"

    log_info "Attempting execution (expect LSM deny + CRITICAL_ALERT JSON)..."
    set +e
    local output
    output="$("${payload_path}" 2>&1)"
    local exit_code=$?
    set -e

    if [[ ${exit_code} -eq 0 ]]; then
        log_warn "Payload executed successfully — LSM did NOT block ${payload_path}."
        log_warn "Ensure agent-ebpf-sensor is running with bprm_check_security attached."
        if [[ -n "${output}" ]]; then
            log_warn "  stdout: ${output}"
        fi
        return 1
    fi

    log_ok "Execution denied by LSM (exit=${exit_code}) — enforcement active for ${staging_prefix}."
    if [[ -n "${output}" ]]; then
        log_info "  kernel/userspace message: ${output}"
    fi
    log_info "Expect sensor stdout: CRITICAL_ALERT / NEUROMESH-EXEC-BLACKLIST-PATH (matched_pattern=${staging_prefix})."
    return 0
}

phase_lsm_staging_paths() {
    log_phase "Phase 2: LSM ephemeral-path enforcement"
    log_mitre "T1204 — User Execution (malicious file staged in world-writable directories)"
    log_info "Testing all LSM deny prefixes: /tmp/, /dev/shm/, /var/tmp/"

    local failures=0
    local path prefix

    for path in "${LSM_STAGING_PATHS[@]}"; do
        case "${path}" in
            /tmp/*)       prefix="/tmp/" ;;
            /dev/shm/*)   prefix="/dev/shm/" ;;
            /var/tmp/*)   prefix="/var/tmp/" ;;
            *)            prefix="unknown" ;;
        esac

        echo
        log_info "── Target: ${path} (prefix ${prefix})"
        if ! attempt_lsm_blocked_exec "${path}" "${prefix}"; then
            failures=$((failures + 1))
        fi
    done

    if [[ ${failures} -gt 0 ]]; then
        log_warn "${failures} staging path(s) were NOT blocked — review sensor attach and CONFIG_BPF_LSM."
    else
        log_ok "All LSM staging paths blocked as expected."
    fi
}

# ---------------------------------------------------------------------------
# Phase 3 — Spawn burst (T1059.004 / behavioral detection)
# ---------------------------------------------------------------------------

phase_t1059_spawn_burst() {
    log_phase "Phase 3: Rapid shell spawn burst"
    log_mitre "T1059.004 — Unix Shell (automated interpreter chaining / post-exploitation)"
    log_mitre "T1499 — Endpoint Denial of Service (fork/exec storm precursor)"
    log_info "Parent tag: ${BURST_PARENT_TAG} | burst size: ${BURST_COUNT}"
    log_info "Expect sensor stdout: BEHAVIOR_ALERT / NEUROMESH-EXEC-SPAWN-BURST."

    # Subshell provides stable ppid for DataNormalizer parent-keyed frequency analysis.
    (
        for _ in $(seq 1 "${BURST_COUNT}"); do
            /bin/sh -c '/usr/bin/true' >/dev/null
        done
    ) &
    wait

    log_ok "Spawn burst complete — review sensor stdout for BEHAVIOR_ALERT JSON."
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    log_phase "Phase 4: Cleanup"
    local artifact
    for artifact in "${CREATED_ARTIFACTS[@]:-}"; do
        rm -f "${artifact}" 2>/dev/null || true
    done
    log_ok "Mock artifacts removed."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    if [[ "${1:-}" == "--kafka" ]]; then
        kafka_simulation
        exit 0
    fi

    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        cat <<EOF
Usage: $(basename "$0") [--kafka]

  (default)  Run live LSM + behavioral simulation (Linux + running sensor).
  --kafka    Inject synthetic telemetry via mock_ebpf_stream.py (no eBPF).

Environment:
  NEUROMESH_BURST_COUNT   Spawn burst size (default: 10)
EOF
        exit 0
    fi

    require_linux
    trap cleanup EXIT

    log_info "Neuromesh v0.1.0-core attack simulation starting..."
    log_info "Monitor agent stdout for JSON alert lines (CRITICAL_ALERT, BEHAVIOR_ALERT)."

    phase_benign_baseline
    phase_lsm_staging_paths
    phase_t1059_spawn_burst

    echo
    log_ok "Simulation finished. Validation checklist:"
    log_info "  [ ] CRITICAL_ALERT for each blocked /tmp/, /dev/shm/, /var/tmp/ execution"
    log_info "  [ ] BEHAVIOR_ALERT for rapid spawn burst (NEUROMESH-EXEC-SPAWN-BURST)"
    log_info "  [ ] No alerts for benign /bin/ls and /bin/cat"
}

main "$@"
