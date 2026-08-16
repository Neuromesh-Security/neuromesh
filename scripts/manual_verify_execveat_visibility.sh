#!/usr/bin/env bash
# Manual verification for Issue #126 — execveat/fexecve telemetry visibility.
#
# Proves on a live kernel that:
#   1. both exec tracepoints load and attach (nm_proc_events + nm_execveat),
#   2. execve(2), execveat(2) and fexecve(3) each reach PROCESS_EVENTS,
#   3. each record is correctly labelled with its originating syscall,
#   4. LSM enforcement is UNCHANGED by this telemetry work (regression guard).
#
# Requires Linux with CONFIG_BPF_LSM, bpffs, CAP_BPF, and a C compiler. Windows +
# Docker Desktop cannot prove tracepoint attach or syscall capture.
#
# Usage: sudo ./scripts/manual_verify_execveat_visibility.sh
set -euo pipefail

AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
WORK_DIR="$(mktemp -d /tmp/nm-execveat-verify.XXXXXX)"
LOG_FILE="${WORK_DIR}/agent.log"
PROBE_BIN="${WORK_DIR}/nm_exec_probe"
DENY_PROBE="/tmp/nm-execveat-enforcement-probe.sh"
EXEC_TARGET="${EXEC_TARGET:-/bin/true}"
AGENT_PID=""

pass() { printf 'PASS: %s\n' "$1"; }
fail() {
    printf 'FAIL: %s\n' "$1" >&2
    printf -- '---- last 60 agent log lines ----\n' >&2
    tail -n 60 "$LOG_FILE" >&2 2>/dev/null || true
    exit 1
}

cleanup() {
    if [[ -n "$AGENT_PID" ]]; then
        kill -TERM "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    rm -f "$DENY_PROBE"
    printf 'Agent log retained at %s\n' "$LOG_FILE"
}
trap cleanup EXIT

echo "== phase 0: preflight =="
[[ "$(uname -s)" == "Linux" ]] || fail "must run on Linux"
test -d /sys/fs/bpf || fail "bpffs not mounted at /sys/fs/bpf"
test -f /sys/kernel/btf/vmlinux || fail "kernel BTF missing (CONFIG_DEBUG_INFO_BTF)"
test -x "$AGENT_BIN" || fail "agent binary not found at ${AGENT_BIN} (cargo build --release --features orchestrator)"
test -x "$EXEC_TARGET" || fail "exec target ${EXEC_TARGET} not executable"
command -v cc >/dev/null || fail "no C compiler (cc) available to build the syscall probe"
# The tracepoint must exist in the kernel's tracefs, or the attach cannot succeed.
test -d /sys/kernel/tracing/events/syscalls/sys_enter_execveat \
    || test -d /sys/kernel/debug/tracing/events/syscalls/sys_enter_execveat \
    || fail "sys_enter_execveat tracepoint not present in tracefs"
mkdir -p "$PIN_ROOT"
# Record the libc version: it determines which lowering fexecve(3) should be
# EXPECTED to take, so phase 5's result is interpretable rather than ambiguous
# between "old libc, working as designed" and "our hook missed it".
printf 'kernel: %s\n' "$(uname -r)"
printf 'libc:   %s\n' "$(ldd --version 2>/dev/null | head -n 1 || echo 'unknown')"
pass "preflight"

echo "== phase 1: build syscall probe =="
# Each mode fires exactly one exec variant with a distinctive argv[0] marker, so
# events are attributable in a noisy log. Markers are deliberately chosen so none
# is a prefix of another, otherwise a grep for one would match another's records.
#
# fexecve(3) and raw execveat+AT_EMPTY_PATH are BOTH probed, and they are not
# substitutes for each other:
#   * fexecve  — the real glibc library call, for ecological validity: it proves
#                the API an attacker or runtime would actually use is captured.
#   * at_empty — the raw AT_EMPTY_PATH syscall, i.e. the exact shape glibc lowers
#                fexecve to. Probed directly so the UNKNOWN-path / PATH_FROM_FD
#                branch is exercised on EVERY host, independent of which lowering
#                this particular libc chooses. Without it, a host whose libc took
#                the legacy /proc/self/fd fallback would leave that branch
#                completely untested while the script still reported success.
cat >"${WORK_DIR}/nm_exec_probe.c" <<'PROBE'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

static int open_target(const char *target)
{
	int fd = open(target, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		perror("open");
	return fd;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"usage: %s <execve|execveat|execveat_empty|fexecve> <target>\n",
			argv[0]);
		return 2;
	}

	const char *mode = argv[1];
	const char *target = argv[2];
	char *envp[] = { NULL };
	int fd;

	/* execve(2) control — the pre-existing telemetry path must stay untouched. */
	if (strcmp(mode, "execve") == 0) {
		char *args[] = { "nm-probe-plain-execve", NULL };

		execve(target, args, envp);
		perror("execve");
		return 1;
	}

	/* execveat(2) with a real path. Exercises the argument shift (dfd at
	 * args[0], pathname at args[1], argv at args[2]) and path resolution.
	 * Issued via raw syscall() so it does not depend on a glibc wrapper.
	 */
	if (strcmp(mode, "execveat") == 0) {
		char *args[] = { "nm-probe-at-path", NULL };

		syscall(SYS_execveat, AT_FDCWD, target, args, envp, 0);
		perror("execveat");
		return 1;
	}

	/* Raw AT_EMPTY_PATH — the exact syscall shape glibc's fexecve emits. */
	if (strcmp(mode, "execveat_empty") == 0) {
		char *args[] = { "nm-probe-at-empty", NULL };

		fd = open_target(target);
		if (fd < 0)
			return 1;
		syscall(SYS_execveat, fd, "", args, envp, AT_EMPTY_PATH);
		perror("execveat AT_EMPTY_PATH");
		return 1;
	}

	/* The real glibc library call. */
	if (strcmp(mode, "fexecve") == 0) {
		char *args[] = { "nm-probe-fexecve", NULL };

		fd = open_target(target);
		if (fd < 0)
			return 1;
		fexecve(fd, args, envp);
		perror("fexecve");
		return 1;
	}

	fprintf(stderr, "unknown mode: %s\n", mode);
	return 2;
}
PROBE
cc -O1 -Wall -o "$PROBE_BIN" "${WORK_DIR}/nm_exec_probe.c" || fail "probe compilation failed"
pass "probe built at ${PROBE_BIN}"

echo "== phase 2: start agent with per-event telemetry tracing =="
# neuromesh::otel=trace logs every decoded ExecEvent's attributes, including the
# Issue #126 neuromesh.exec.syscall discriminator.
RUST_LOG="${RUST_LOG:-info,neuromesh::otel=trace}" "$AGENT_BIN" >"$LOG_FILE" 2>&1 &
AGENT_PID=$!

for _ in $(seq 1 30); do
    if grep -q "Process visibility armed" "$LOG_FILE" 2>/dev/null; then
        break
    fi
    kill -0 "$AGENT_PID" 2>/dev/null || fail "agent exited during startup"
    sleep 1
done
grep -q "Process visibility armed" "$LOG_FILE" || fail "agent never armed process visibility within 30s"
grep -q "sys_enter_execveat" "$LOG_FILE" \
    || fail "startup log does not mention sys_enter_execveat — old binary? rebuild required"
pass "agent armed (pid ${AGENT_PID})"

echo "== phase 3: confirm both tracepoint programs are loaded =="
if command -v bpftool >/dev/null; then
    for prog in nm_proc_events nm_execveat; do
        bpftool prog show 2>/dev/null | grep -q "$prog" \
            || fail "bpftool does not show loaded program ${prog}"
        pass "program loaded: ${prog}"
    done
    if bpftool perf show 2>/dev/null | grep -q 'execveat'; then
        pass "bpftool perf shows an execveat attachment"
    else
        echo "NOTE: bpftool perf did not list execveat (kernels do not always report"
        echo "      tracepoint attachments here) — the log evidence below is authoritative"
    fi
else
    echo "NOTE: bpftool unavailable — skipping kernel-side program listing"
fi

echo "== phase 4: fire each exec variant =="
for mode in execve execveat execveat_empty fexecve; do
    rc=0
    "$PROBE_BIN" "$mode" "$EXEC_TARGET" || rc=$?
    [[ "$rc" -eq 0 ]] || fail "probe ${mode} failed to exec ${EXEC_TARGET} (exit ${rc})"
    pass "probe ${mode} executed"
done
# Allow the async RingBuf poller and worker to drain.
sleep 3

echo "== phase 5: assert each variant is visible AND correctly labelled =="
#
# These needles match the tracing Debug rendering of OtelExecAttributes, whose
# BTreeMap<String, String> prints as {"key": "value"}. The trailing quote in the
# syscall needles matters: without it, "execve" would also match "execveat".
SYSCALL_IS_EXECVE='neuromesh.exec.syscall": "execve"'
SYSCALL_IS_EXECVEAT='neuromesh.exec.syscall": "execveat"'
FILENAME_IS_UNKNOWN='neuromesh.filename": "UNKNOWN:filename_capture_fault"'
# Only inserted when the flag is set, so key presence alone is a valid assertion.
PATH_FROM_FD_SET='neuromesh.exec.path_from_fd'

# Most recent telemetry record carrying a given argv[0] marker. Locating a record
# BY its argv marker simultaneously proves argv survived capture — which is what
# keeps an UNKNOWN-path event useful for attribution.
record_for() { grep -F "$1" "$LOG_FILE" | tail -n 1; }

assert_in_record() {
    local label="$1" record="$2" needle="$3" why="$4"

    grep -qF "$needle" <<<"$record" || fail "${label}: expected [${needle}] — ${why}
  record: ${record}"
}

# --- execve(2) control: the pre-existing path must be unchanged. ---
rec="$(record_for 'nm-probe-plain-execve')"
[[ -n "$rec" ]] || fail "execve(2) control produced no telemetry record"
assert_in_record "execve(2)" "$rec" "$SYSCALL_IS_EXECVE" \
    "the control must not be relabelled as execveat"
assert_in_record "execve(2)" "$rec" "$EXEC_TARGET" \
    "the control must still resolve its path"
pass "execve(2) visible, labelled execve, path resolved"

# --- execveat(2) with a path: validates the tracepoint ARGUMENT SHIFT. ---
# execveat puts dfd at args[0], so pathname is args[1] and argv args[2]. A
# regression to the execve indices would read dfd as a userspace pointer; the
# resolved-path assertion is what catches that, since mere event presence would not.
rec="$(record_for 'nm-probe-at-path')"
[[ -n "$rec" ]] || fail "execveat(2) produced no telemetry record"
assert_in_record "execveat(2)" "$rec" "$SYSCALL_IS_EXECVEAT" \
    "record must be labelled as originating from execveat"
assert_in_record "execveat(2)" "$rec" "$EXEC_TARGET" \
    "path did not resolve — tracepoint argument indices are likely wrong \
(pathname must be args[1], argv args[2])"
pass "execveat(2) visible, labelled execveat, path resolved to ${EXEC_TARGET}"

# --- raw execveat + AT_EMPTY_PATH: asserts the FULL nuanced labelling. ---
# This is the deterministic proof of the fd-named case: it does not depend on how
# this host's libc implements fexecve. All three properties are asserted, not just
# "an event appeared".
rec="$(record_for 'nm-probe-at-empty')"
[[ -n "$rec" ]] || fail "execveat+AT_EMPTY_PATH produced no telemetry record"
assert_in_record "AT_EMPTY_PATH" "$rec" "$SYSCALL_IS_EXECVEAT" \
    "fd-named exec must still be labelled execveat"
assert_in_record "AT_EMPTY_PATH" "$rec" "$FILENAME_IS_UNKNOWN" \
    "empty path string must surface as the UNKNOWN sentinel, never as an empty path"
assert_in_record "AT_EMPTY_PATH" "$rec" "$PATH_FROM_FD_SET" \
    "an fd-named exec must be distinguishable from a probe fault"
pass "execveat+AT_EMPTY_PATH: labelled execveat, filename UNKNOWN, path_from_fd set, argv captured"

# --- fexecve(3): the real library call. ---
# Which syscall this lowers to is a libc property, so both outcomes are accepted —
# but each is asserted in full rather than waved through as "some event appeared".
rec="$(record_for 'nm-probe-fexecve')"
[[ -n "$rec" ]] || fail "fexecve(3) produced no telemetry record"
if grep -qF "$PATH_FROM_FD_SET" <<<"$rec"; then
    # Modern glibc (>= 2.27) / musl: execveat(fd, "", …, AT_EMPTY_PATH).
    assert_in_record "fexecve(3)" "$rec" "$SYSCALL_IS_EXECVEAT" \
        "the AT_EMPTY_PATH lowering enters via execveat"
    assert_in_record "fexecve(3)" "$rec" "$FILENAME_IS_UNKNOWN" \
        "the AT_EMPTY_PATH lowering carries no path string"
    pass "fexecve(3) lowered to execveat+AT_EMPTY_PATH — labelled execveat, filename UNKNOWN, path_from_fd set"
else
    # Legacy ENOSYS fallback: execve("/proc/self/fd/N", …).
    assert_in_record "fexecve(3)" "$rec" "$SYSCALL_IS_EXECVE" \
        "the /proc/self/fd fallback enters via execve, not execveat"
    assert_in_record "fexecve(3)" "$rec" '/proc/self/fd/' \
        "the fallback must resolve to a /proc/self/fd path"
    pass "fexecve(3) lowered to execve(/proc/self/fd/N) — captured by the pre-existing attach"
    echo "NOTE: this libc does not use execveat+AT_EMPTY_PATH for fexecve (glibc:"
    echo "      $(ldd --version 2>/dev/null | head -n 1)). The AT_EMPTY_PATH branch"
    echo "      is still proven by the execveat_empty probe asserted above."
fi

echo "== phase 6: enforcement regression guard (must be UNCHANGED) =="
# Issue #126 is telemetry-only. A blacklisted-path exec must still be denied, and
# it must still be denied via execveat as well as execve.
printf '#!/bin/sh\necho should-not-run\n' >"$DENY_PROBE"
chmod +x "$DENY_PROBE"

if "$DENY_PROBE" 2>/dev/null; then
    fail "blacklisted /tmp/ payload executed via execve — ENFORCEMENT REGRESSION"
fi
pass "execve deny still enforced for /tmp/"

if "$PROBE_BIN" execveat "$DENY_PROBE" 2>/dev/null; then
    fail "blacklisted /tmp/ payload executed via execveat — ENFORCEMENT REGRESSION"
fi
pass "execveat deny still enforced for /tmp/ (shared bprm_check_security hook)"

echo
echo "ALL MANUAL CHECKS PASSED — execveat/fexecve telemetry visible, enforcement unchanged."
