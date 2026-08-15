#!/usr/bin/env bash
# Install CI build dependencies via apt with bounded, self-healing retries.
#
# Background (Production CI run 31908411229, PR #123): `apt-get update` stalled
# mid-transfer against http://azure.archive.ubuntu.com and printed nothing for
# 14m17s, until the job's own `timeout-minutes: 15` cancelled it. apt's built-in
# Acquire timeouts never tripped, the log ended on a bare "The operation was
# canceled", and because the stall ate the whole job budget it also took down the
# four required checks that depend on Lint. Re-running the identical commit
# installed the same packages in 31s, so the mirror was the flaky part, not the
# package set — the same class of registry flake already absorbed by the BuildKit
# retry in security-scan-pipeline.yml (PR #79 / Issue #78).
#
# Two guarantees follow from that: every apt call is wall-clock capped so no
# single call can hang a job, and a genuine mirror outage exits non-zero with an
# explicit infrastructure-failure message instead of a silent cancellation.
#
# Usage: scripts/ci_apt_install.sh clang llvm cmake …
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "::error::ci_apt_install.sh requires at least one package name" >&2
  exit 2
fi

ATTEMPTS="${CI_APT_ATTEMPTS:-3}"
# Historical duration of these installs is 11-32s (30 runs, Aug 12-15), so a 90s
# cap per apt call leaves generous headroom for a merely-slow mirror while still
# bounding the worst case to ~9.5min, safely inside the caller's step timeout.
CALL_TIMEOUT_SECS="${CI_APT_CALL_TIMEOUT_SECS:-90}"

# Make apt itself give up on a dead mirror quickly rather than relying solely on
# the outer `timeout` backstop.
apt_opts=(
  -o Acquire::Retries=2
  -o Acquire::http::Timeout=15
  -o Acquire::https::Timeout=15
)

# The stall was mirror-specific: azure.archive.ubuntu.com hung while
# archive.ubuntu.com kept serving in the very same apt run. Dropping the Azure
# mirror is therefore a targeted last resort, not a blind retry.
switch_to_canonical_mirror() {
  local files
  files="$(grep -rls 'azure.archive.ubuntu.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true)"
  [[ -n "$files" ]] || return 1
  printf '%s\n' "$files" \
    | xargs -r sudo sed -i 's|://azure.archive.ubuntu.com/ubuntu|://archive.ubuntu.com/ubuntu|g'
}

run_attempt() {
  sudo timeout --kill-after=10 "$CALL_TIMEOUT_SECS" apt-get "${apt_opts[@]}" update \
    && sudo timeout --kill-after=10 "$CALL_TIMEOUT_SECS" apt-get "${apt_opts[@]}" install -y "$@"
}

for attempt in $(seq 1 "$ATTEMPTS"); do
  if (( attempt == ATTEMPTS )) && switch_to_canonical_mirror; then
    echo "apt attempt ${attempt}/${ATTEMPTS}: dropped azure.archive.ubuntu.com for archive.ubuntu.com"
  fi

  echo "apt attempt ${attempt}/${ATTEMPTS} (each apt call capped at ${CALL_TIMEOUT_SECS}s): $*"
  if run_attempt "$@"; then
    echo "OK: apt installed $# package(s) on attempt ${attempt}/${ATTEMPTS}"
    exit 0
  fi

  echo "apt attempt ${attempt}/${ATTEMPTS} failed or exceeded its ${CALL_TIMEOUT_SECS}s cap" >&2
  if (( attempt < ATTEMPTS )); then
    # A killed `apt-get install` can leave dpkg mid-transaction; clear it so the
    # next attempt fails on the mirror (what we are retrying) and not on state.
    sudo dpkg --configure -a || true
    sleep $(( attempt * 5 ))
  fi
done

echo "::error::apt dependency install failed after ${ATTEMPTS} attempts, each apt call capped at ${CALL_TIMEOUT_SECS}s. Ubuntu package mirrors were unreachable or stalled — this is a CI infrastructure/network failure, NOT a code failure. Re-run the job first; if it recurs, check https://status.canonical.com and the runner's /etc/apt/apt-mirrors.txt." >&2
exit 1
