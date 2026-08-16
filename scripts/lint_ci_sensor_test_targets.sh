#!/usr/bin/env bash
# Fail CI if any apps/agent-ebpf-sensor/tests/*.rs integration target is not
# referenced by an explicit `cargo test -p agent-ebpf-sensor --test <name>` in
# .github/workflows/ci.yml.
#
# Why: the Test job hand-enumerates sensor --test targets (different files need
# different flags: chaos → --features orchestrator, execve_stress → --no-run).
# Full auto-discovery is unsafe; forgetting to add a step leaves a new file
# green in CI with zero executions (Issue #128 Gap D / bpf_attach_contract class).
#
# This guard only asserts enumeration completeness — not feature correctness.
# Reverse check (ci.yml --test name with no file) is deferred: cargo already
# fails loudly with `error: no test target named X` (verified).
#
# Uses find/grep/sed/sort only (no ripgrep) so Lint (work) works on stock
# ubuntu-latest runners — same constraint as lint_bpf_obj_names.sh.
#
# Overrides for fixtures / self-test:
#   NM_SENSOR_TESTS_DIR  — directory of *.rs targets (default: <root>/apps/.../tests)
#   NM_CI_YML            — workflow file to scan (default: <root>/.github/workflows/ci.yml)
#
# Usage:
#   bash scripts/lint_ci_sensor_test_targets.sh
#   bash scripts/lint_ci_sensor_test_targets.sh --self-test
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

list_filesystem_targets() {
  local tests_dir="$1"
  if [[ ! -d "$tests_dir" ]]; then
    echo "ERROR: sensor tests directory not found: $tests_dir" >&2
    return 2
  fi
  # Top-level only — exclude helpers under tests/common/.
  find "$tests_dir" -maxdepth 1 -type f -name '*.rs' -printf '%f\n' \
    | sed 's/\.rs$//' \
    | sort -u
}

list_ci_enumerated_targets() {
  local ci_yml="$1"
  if [[ ! -f "$ci_yml" ]]; then
    echo "ERROR: ci.yml not found: $ci_yml" >&2
    return 2
  fi
  # Match: cargo test -p agent-ebpf-sensor --test NAME
  # Allows trailing flags (--features, --no-run) on the same line.
  grep -E 'cargo[[:space:]]+test[[:space:]]+-p[[:space:]]+agent-ebpf-sensor[[:space:]]+--test[[:space:]]+' "$ci_yml" \
    | sed -E 's/.*--test[[:space:]]+([A-Za-z0-9_]+).*/\1/' \
    | sort -u
}

lint_sensor_test_targets() {
  local tests_dir="$1"
  local ci_yml="$2"
  local fs_list ci_list missing
  local fail=0

  fs_list="$(list_filesystem_targets "$tests_dir")"
  ci_list="$(list_ci_enumerated_targets "$ci_yml")"

  if [[ -z "$fs_list" ]]; then
    echo "ERROR: found zero top-level *.rs targets under $tests_dir — scanner broken?" >&2
    return 2
  fi

  echo "== sensor integration test targets (must appear as --test in ci.yml) =="
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    if grep -qxF "$name" <<<"$ci_list"; then
      printf '  %-40s enumerated\n' "$name"
    else
      printf '  %-40s MISSING\n' "$name"
      echo "FAIL: apps/agent-ebpf-sensor/tests/${name}.rs is not referenced by any" >&2
      echo "      \`cargo test -p agent-ebpf-sensor --test ${name}\` in ci.yml's test job." >&2
      echo "      Add an explicit step (with the correct --features / --no-run) before merging." >&2
      fail=1
      missing="${missing:-}${name} "
    fi
  done <<<"$fs_list"

  if (( fail != 0 )); then
    echo "sensor test-target enumeration lint FAILED (missing: ${missing% })" >&2
    return 1
  fi

  local count
  count="$(grep -c . <<<"$fs_list" || true)"
  echo "OK: ${count} sensor integration test target(s) enumerated in ci.yml"
  return 0
}

run_self_test() {
  local pass_dir fail_dir pass_yml fail_yml
  # Not `local`: the EXIT trap must still see this path under `set -u` when
  # the function returns (locals are unbound before the trap runs).
  SELFTEST_TMP="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf \"$SELFTEST_TMP\"" EXIT

  pass_dir="${SELFTEST_TMP}/pass/tests"
  fail_dir="${SELFTEST_TMP}/fail/tests"
  pass_yml="${SELFTEST_TMP}/pass/ci.yml"
  fail_yml="${SELFTEST_TMP}/fail/ci.yml"
  mkdir -p "$pass_dir" "$fail_dir"

  # (a) All three targets enumerated → must PASS.
  touch "${pass_dir}/alpha_test.rs" "${pass_dir}/beta_test.rs" "${pass_dir}/gamma_test.rs"
  mkdir -p "${pass_dir}/common"
  touch "${pass_dir}/common/mod.rs" # helper — must be ignored
  cat >"$pass_yml" <<'EOF'
jobs:
  test:
    steps:
      - run: cargo test -p agent-ebpf-sensor --test alpha_test
      - run: |
          cargo test -p agent-ebpf-sensor --test beta_test --features orchestrator
          cargo test -p agent-ebpf-sensor --test gamma_test --no-run
EOF

  echo "== self-test (a): complete enumeration must PASS =="
  if ! lint_sensor_test_targets "$pass_dir" "$pass_yml"; then
    echo "SELF-TEST FAIL: expected pass fixture to succeed" >&2
    return 1
  fi

  # (b) One target missing from ci.yml → must FAIL with expected message.
  touch "${fail_dir}/alpha_test.rs" "${fail_dir}/orphan_unenumerated_test.rs"
  cat >"$fail_yml" <<'EOF'
jobs:
  test:
    steps:
      - run: cargo test -p agent-ebpf-sensor --test alpha_test
EOF

  echo "== self-test (b): missing enumeration must FAIL =="
  local out rc=0
  out="$(lint_sensor_test_targets "$fail_dir" "$fail_yml" 2>&1)" || rc=$?
  echo "$out"
  if [[ "$rc" -eq 0 ]]; then
    echo "SELF-TEST FAIL: expected fail fixture to exit non-zero" >&2
    return 1
  fi
  if ! grep -qF 'orphan_unenumerated_test.rs is not referenced by any' <<<"$out"; then
    echo "SELF-TEST FAIL: expected error message about orphan_unenumerated_test.rs" >&2
    return 1
  fi
  if ! grep -qF 'cargo test -p agent-ebpf-sensor --test orphan_unenumerated_test' <<<"$out"; then
    echo "SELF-TEST FAIL: expected remediation hint naming the missing --test" >&2
    return 1
  fi

  echo "OK: self-test passed (pass fixture green, fail fixture red with expected message)"
  trap - EXIT
  rm -rf "$SELFTEST_TMP"
  unset SELFTEST_TMP
  return 0
}

main() {
  if [[ "${1:-}" == "--self-test" ]]; then
    run_self_test
    return $?
  fi

  local tests_dir ci_yml
  tests_dir="${NM_SENSOR_TESTS_DIR:-$ROOT/apps/agent-ebpf-sensor/tests}"
  ci_yml="${NM_CI_YML:-$ROOT/.github/workflows/ci.yml}"
  lint_sensor_test_targets "$tests_dir" "$ci_yml"
}

main "$@"
