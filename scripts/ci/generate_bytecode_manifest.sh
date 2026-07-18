#!/usr/bin/env bash
# Generate the Phase 1 signed-bytecode JSON manifest (Issue #44).
#
# Digests MUST be computed from the exact files that cargo `include_bytes!`
# into the agent binary in the same build (sys_exec.bpf.o, network_filter.bpf.o,
# agent-ebpf-sensor-ebpf). The agent binary itself is intentionally omitted —
# self-digest coverage is circular; image-level Cosign signing covers that layer.
set -euo pipefail

SYS_EXEC=""
NETWORK_FILTER=""
ENFORCEMENT=""
GIT_SHA="unknown"
BUILD_TIMESTAMP=""
OUT=""

usage() {
  cat <<'EOF'
Usage: generate_bytecode_manifest.sh \
  --sys-exec PATH --network-filter PATH --enforcement PATH \
  --out PATH [--git-sha SHA] [--build-timestamp RFC3339]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sys-exec) SYS_EXEC="${2:?}"; shift 2 ;;
    --network-filter) NETWORK_FILTER="${2:?}"; shift 2 ;;
    --enforcement) ENFORCEMENT="${2:?}"; shift 2 ;;
    --git-sha) GIT_SHA="${2:?}"; shift 2 ;;
    --build-timestamp) BUILD_TIMESTAMP="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "${SYS_EXEC}" || -z "${NETWORK_FILTER}" || -z "${ENFORCEMENT}" || -z "${OUT}" ]]; then
  usage >&2
  exit 2
fi

for f in "${SYS_EXEC}" "${NETWORK_FILTER}" "${ENFORCEMENT}"; do
  if [[ ! -f "${f}" ]]; then
    echo "ERROR: artifact not found: ${f}" >&2
    exit 1
  fi
done

if [[ -z "${BUILD_TIMESTAMP}" ]]; then
  BUILD_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
fi

# Reject characters that would break the compact JSON we emit below.
for value_name in GIT_SHA BUILD_TIMESTAMP; do
  value="${!value_name}"
  if [[ "${value}" == *\"* || "${value}" == *\\* ]]; then
    echo "ERROR: ${value_name} contains characters unsafe for JSON embedding" >&2
    exit 1
  fi
done

digest_of() {
  local path="$1"
  local hex
  hex="$(sha256sum -- "${path}" | awk '{print $1}')"
  printf 'sha256:%s' "${hex}"
}

SYS_DIGEST="$(digest_of "${SYS_EXEC}")"
NET_DIGEST="$(digest_of "${NETWORK_FILTER}")"
ENF_DIGEST="$(digest_of "${ENFORCEMENT}")"

mkdir -p "$(dirname "${OUT}")"

# Compact, deterministic field order — Cosign signs these exact bytes.
# Do not pretty-print; the agent verifies the signature over the on-disk file
# and must never re-serialize before checking the signature.
printf '%s\n' \
  "{\"schema_version\":1,\"git_sha\":\"${GIT_SHA}\",\"build_timestamp\":\"${BUILD_TIMESTAMP}\",\"artifacts\":[{\"name\":\"sys_exec.bpf.o\",\"digest\":\"${SYS_DIGEST}\"},{\"name\":\"network_filter.bpf.o\",\"digest\":\"${NET_DIGEST}\"},{\"name\":\"agent-ebpf-sensor-ebpf\",\"digest\":\"${ENF_DIGEST}\"}]}" \
  > "${OUT}"

echo "wrote ${OUT}"
