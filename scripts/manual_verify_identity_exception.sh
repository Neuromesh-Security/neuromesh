#!/usr/bin/env bash
# Manual verification for Slice 2a — /tmp/ identity exceptions (Issue #78 / PR #79).
#
# Requires: Linux root, CONFIG_BPF_LSM, bpffs, cgroup v2, bpftool, python3,
# Cosign attestation material already configured for the agent (same as
# manual_verify_lsm_pin.sh / manual_verify_runtime_integrity.sh).
#
# This environment (Windows / non-LSM hosts) cannot prove kernel allow/deny.
# Run on the droplet (or equivalent BPF-LSM node).
#
# Cgroup placement (concrete, not hand-waved):
#   bpf_get_current_cgroup_id() returns the cgroupfs inode of the task's cgroup
#   (cgroup v2). We mkdir two leaf cgroups under /sys/fs/cgroup, read each
#   directory's inode via `stat -c '%i'`, seed ONE inode into
#   NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS, then run payloads by writing $BASHPID
#   into that cgroup's cgroup.procs before exec — same ID the LSM helper sees.
#
# Scenarios (all required):
#   1) Bundle stub (schema_version 2) with short expires_at serves /v1/policy-bundle
#   2) Agent syncs → ID_EXCEPT_VALID[0] == 1 (bpftool evidence)
#   3) Manual seed env emits SECURITY WARNING; allow map contains seeded id
#   4) Seeded cgroup + /tmp/ exec → ALLOW (exit 0)
#   5) Non-seeded cgroup + /tmp/ exec → DENY (non-zero)
#   6) Seeded cgroup + /dev/shm/ and /var/tmp/ → DENY (scope /tmp/-only)
#   7) TTL expiry (or forced VALID=0) → same seeded /tmp/ exec → DENY
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
TEST_ROOT="${NEUROMESH_IDENTITY_TEST_ROOT:-/opt/neuromesh-test}"
BUNDLE_TOKEN="${NEUROMESH_POLICY_BUNDLE_TOKEN:-slice2a-manual-verify-token}"
PE_PORT="${NEUROMESH_IDENTITY_TEST_PE_PORT:-18080}"
# Short TTL so scenario 7 can wait without the production 90s default.
TEST_TTL_SECS="${NEUROMESH_IDENTITY_TEST_TTL_SECS:-45}"
# If 1, skip waiting for wall-clock TTL and bpftool-update VALID=0 instead.
FORCE_VALID_ZERO="${NEUROMESH_IDENTITY_TEST_FORCE_VALID_ZERO:-0}"
AGENT_LOG="${NEUROMESH_IDENTITY_TEST_AGENT_LOG:-${TEST_ROOT}/identity-exception-agent.log}"
STUB_LOG="${TEST_ROOT}/identity-exception-stub.log"
CG_ALLOW="${TEST_ROOT}/cgroup-allow"
CG_DENY="${TEST_ROOT}/cgroup-deny"
# Payloads under deny prefixes (intentional).
PAYLOAD_TMP="${TEST_ROOT_PAYLOAD_TMP:-/tmp/neuromesh-slice2a-allow.sh}"
PAYLOAD_SHM="${TEST_ROOT_PAYLOAD_SHM:-/dev/shm/neuromesh-slice2a-shm.sh}"
PAYLOAD_VTMP="${TEST_ROOT_PAYLOAD_VTMP:-/var/tmp/neuromesh-slice2a-vtmp.sh}"

PASS_COUNT=0
fail() {
  echo "FAIL: $*" >&2
  exit 1
}
pass() {
  echo "PASS: $*"
  PASS_COUNT=$((PASS_COUNT + 1))
}

echo "== preflight =="
test "$(id -u)" -eq 0 || fail "must run as root (cgroup.procs + LSM attach)"
test -x "$AGENT_BIN" || fail "AGENT_BIN not executable: $AGENT_BIN"
test -d /sys/fs/bpf || fail "/sys/fs/bpf missing"
test -f /sys/kernel/btf/vmlinux || fail "BTF missing at /sys/kernel/btf/vmlinux"
command -v bpftool >/dev/null || fail "bpftool required"
command -v python3 >/dev/null || fail "python3 required for bundle stub"
mount | grep -Eq 'type bpf|bpffs' || mount -t bpf bpf /sys/fs/bpf || true
mkdir -p "$PIN_ROOT" "$TEST_ROOT"

# --- cgroup v2 leaf dirs; inode == bpf_get_current_cgroup_id() ---
if ! mount | grep -q 'cgroup2'; then
  # Unified hierarchy still exposes cgroup2 at /sys/fs/cgroup on modern hosts.
  test -f /sys/fs/cgroup/cgroup.controllers \
    || fail "cgroup v2 required (no /sys/fs/cgroup/cgroup.controllers)"
fi

# Place leaf cgroups under a dedicated subtree we own (avoids fighting systemd).
CG_BASE="/sys/fs/cgroup/neuromesh-slice2a-$$"
mkdir -p "$CG_BASE/allow" "$CG_BASE/deny"
# Record paths for cleanup; also symlink into TEST_ROOT for operator visibility.
ln -sfn "$CG_BASE/allow" "$CG_ALLOW"
ln -sfn "$CG_BASE/deny" "$CG_DENY"
ALLOW_CG_ID="$(stat -c '%i' "$CG_BASE/allow")"
DENY_CG_ID="$(stat -c '%i' "$CG_BASE/deny")"
test -n "$ALLOW_CG_ID" && test "$ALLOW_CG_ID" -gt 0
test -n "$DENY_CG_ID" && test "$DENY_CG_ID" -gt 0
test "$ALLOW_CG_ID" != "$DENY_CG_ID" || fail "allow/deny cgroup inodes collided"
echo "cgroup allow inode (seeded id)=$ALLOW_CG_ID path=$CG_BASE/allow"
echo "cgroup deny  inode (control)=$DENY_CG_ID path=$CG_BASE/deny"

u64_le_hex() {
  python3 -c "import struct,sys; print(' '.join(f'{b:02x}' for b in struct.pack('<Q', int(sys.argv[1]))))" "$1"
}

read_valid_flag() {
  # Prefer JSON; fall back to text dump "value: 01".
  # Map kernel name is ID_EXCEPT_VALID (≤15 chars; was IDENTITY_EXCEPTIONS_VALID).
  if out="$(bpftool -j map dump name ID_EXCEPT_VALID 2>/dev/null)"; then
    python3 -c '
import json,sys
data=json.load(sys.stdin)
entry=data[0]
val=entry.get("value", entry)
if isinstance(val, dict):
    val=val.get("value", val)
if isinstance(val, list):
    print(int(val[0]))
else:
    print(int(val))
' <<<"$out"
    return 0
  fi
  bpftool map dump name ID_EXCEPT_VALID 2>/dev/null \
    | python3 -c '
import re,sys
for line in sys.stdin:
    m=re.search(r"value:\s*([0-9a-fA-F]+)", line)
    if m:
        print(int(m.group(1), 16))
        break
else:
    sys.exit(1)
'
}

wait_valid_flag() {
  local want="$1"
  local deadline=$((SECONDS + 90))
  local got=""
  while (( SECONDS < deadline )); do
    if got="$(read_valid_flag 2>/dev/null)"; then
      if [[ "$got" == "$want" ]]; then
        echo "$got"
        return 0
      fi
    fi
    sleep 1
  done
  echo "last=$(read_valid_flag 2>/dev/null || echo unreadable)" >&2
  return 1
}

lookup_allow_cgroup() {
  local id="$1"
  local key
  key="$(u64_le_hex "$id")"
  # shellcheck disable=SC2086
  bpftool map lookup name ID_ALLOW_CGROUP key hex $key 2>/dev/null
}

# Run argv inside a specific cgroup leaf (cgroup v2).
# Mechanism: bash subshell writes $BASHPID into cgroup.procs, then exec's the
# payload so the LSM sees bpf_get_current_cgroup_id() == that cgroup's inode.
run_in_cgroup() {
  local cg_dir="$1"
  shift
  (
    echo "$BASHPID" >"${cg_dir}/cgroup.procs"
    exec "$@"
  )
}

expect_deny() {
  local label="$1"
  local cg_dir="$2"
  local payload="$3"
  local rc=0
  set +e
  run_in_cgroup "$cg_dir" "$payload"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    fail "${label}: expected DENY (EPERM) but payload exited 0"
  fi
  pass "${label} (exit=${rc})"
}

expect_allow() {
  local label="$1"
  local cg_dir="$2"
  local payload="$3"
  local out=""
  local rc=0
  set +e
  out="$(run_in_cgroup "$cg_dir" "$payload")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    fail "${label}: expected ALLOW but exit=${rc}"
  fi
  echo "$out" | grep -q 'neuromesh-slice2a-ok' \
    || fail "${label}: payload ran but missing ok marker (out=${out})"
  pass "${label}"
}

write_payload() {
  local path="$1"
  printf '#!/bin/sh\necho neuromesh-slice2a-ok\n' >"$path"
  chmod +x "$path"
}

# --- scenario 1: authenticated schema_version:2 stub with short expires_at ---
echo "== scenario 1: start policy-bundle stub (schema_version 2, TTL=${TEST_TTL_SECS}s) =="
STUB_PY="${TEST_ROOT}/slice2a_bundle_stub.py"
cat >"$STUB_PY" <<'PY'
#!/usr/bin/env python3
"""Minimal GET /v1/policy-bundle stub matching Slice 2a wire format."""
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = os.environ["NEUROMESH_POLICY_BUNDLE_TOKEN"]
TTL = int(os.environ.get("NEUROMESH_IDENTITY_TEST_TTL_SECS", "45"))
PORT = int(os.environ.get("NEUROMESH_IDENTITY_TEST_PE_PORT", "18080"))

PREFIXES = ["/tmp/", "/dev/shm/", "/var/tmp/"]
SPIFFE = [
    "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
]
SCOPE = "/tmp/"


def content_version():
    blob = "deny:\n" + "\n".join(PREFIXES) + "\nscope:\n" + SCOPE + "\nspiffe:\n" + "\n".join(SPIFFE)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def bundle():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    exp = now + timedelta(seconds=TTL)
    return {
        "schema_version": 2,
        "version": content_version(),
        "deny_path_prefixes": PREFIXES,
        "identity_allow_exceptions": {
            "scope_path_prefix": SCOPE,
            "spiffe_ids": SPIFFE,
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    }


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        if self.path.split("?", 1)[0] != "/v1/policy-bundle":
            self.send_error(404)
            return
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {TOKEN}":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="neuromesh-policy-bundle"')
            self.end_headers()
            self.wfile.write(b"unauthorized")
            return
        body = json.dumps(bundle()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY
chmod +x "$STUB_PY"

export NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN"
export NEUROMESH_IDENTITY_TEST_TTL_SECS="$TEST_TTL_SECS"
export NEUROMESH_IDENTITY_TEST_PE_PORT="$PE_PORT"
: >"$STUB_LOG"
python3 "$STUB_PY" >>"$STUB_LOG" 2>&1 &
STUB_PID=$!
sleep 1
kill -0 "$STUB_PID" || fail "bundle stub failed to start (see $STUB_LOG)"

# Prove stub shape before agent start.
STUB_BODY="$(curl -sf -H "Authorization: Bearer ${BUNDLE_TOKEN}" \
  "http://127.0.0.1:${PE_PORT}/v1/policy-bundle")" \
  || fail "stub GET /v1/policy-bundle failed"
echo "$STUB_BODY" | python3 -c '
import json,sys
b=json.load(sys.stdin)
assert b["schema_version"]==2, b
assert b["identity_allow_exceptions"]["scope_path_prefix"]=="/tmp/", b
assert b["identity_allow_exceptions"]["spiffe_ids"], b
assert "expires_at" in b["identity_allow_exceptions"], b
print("stub ok expires_at=", b["identity_allow_exceptions"]["expires_at"])
'
pass "scenario 1: schema_version 2 stub serving identity_allow_exceptions"

AGENT_PID=""
cleanup() {
  if [[ -n "${AGENT_PID}" ]]; then
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n "${STUB_PID:-}" ]]; then
    kill -TERM "$STUB_PID" 2>/dev/null || true
    wait "$STUB_PID" 2>/dev/null || true
  fi
  rm -f "$PAYLOAD_TMP" "$PAYLOAD_SHM" "$PAYLOAD_VTMP"
  # Move any leftover tasks out before rmdir (best-effort).
  if [[ -d "${CG_BASE:-}" ]]; then
    for d in "$CG_BASE/allow" "$CG_BASE/deny"; do
      if [[ -f "$d/cgroup.procs" ]]; then
        while read -r p; do
          echo "$p" >/sys/fs/cgroup/cgroup.procs 2>/dev/null || true
        done <"$d/cgroup.procs" || true
      fi
    done
    rmdir "$CG_BASE/allow" "$CG_BASE/deny" "$CG_BASE" 2>/dev/null || true
  fi
  rm -f "$CG_ALLOW" "$CG_DENY"
}
trap cleanup EXIT

# --- scenario 2+3: start agent with manual seed + PE URL ---
echo "== scenario 2+3: start agent (seed=${ALLOW_CG_ID}, PE=127.0.0.1:${PE_PORT}) =="
: >"$AGENT_LOG"
export NEUROMESH_ZT_POLICY_ENGINE_URL="http://127.0.0.1:${PE_PORT}"
export NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN"
# Prefer env token for this harness — never inherit a k8s TOKEN_FILE mount.
unset NEUROMESH_POLICY_BUNDLE_TOKEN_FILE || true
export NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS="$ALLOW_CG_ID"
export NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT"
# Integrity exit would abort mid-test if pins are manipulated elsewhere.
export NEUROMESH_INTEGRITY_EXIT_ON_FAILURE="${NEUROMESH_INTEGRITY_EXIT_ON_FAILURE:-false}"
# Sync success/failure lines are tracing::info!/warn! — default filter is error-only.
export RUST_LOG="${RUST_LOG:-neuromesh=info,neuromesh::policy_sync=info,neuromesh::identity_allow=info}"

# shellcheck disable=SC2086
"$AGENT_BIN" >>"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

# Loud warning must appear (hardening requirement).
for _ in $(seq 1 30); do
  if grep -q "SECURITY WARNING: NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS" "$AGENT_LOG"; then
    break
  fi
  sleep 0.2
done
grep -q "SECURITY WARNING: NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS" "$AGENT_LOG" \
  || fail "scenario 3: SECURITY WARNING missing from agent log ($AGENT_LOG)"
pass "scenario 3: loud SECURITY WARNING for manual cgroup seed"

# Wait for LSM pins + identity VALID=1.
for _ in $(seq 1 60); do
  if kill -0 "$AGENT_PID" 2>/dev/null \
    && test -f "$PIN_ROOT/neuromesh_lsm_exec_guard_link" \
    && test -f "$PIN_ROOT/PATH_DENY_LIST"; then
    break
  fi
  sleep 1
done
kill -0 "$AGENT_PID" || fail "agent died during startup (see $AGENT_LOG)"
test -f "$PIN_ROOT/neuromesh_lsm_exec_guard_link" || fail "LSM link pin missing"

if ! wait_valid_flag 1 >/dev/null; then
  echo "--- agent log (tail) ---" >&2
  tail -n 80 "$AGENT_LOG" >&2 || true
  fail "scenario 2: ID_EXCEPT_VALID did not become 1 within 90s"
fi
VALID_NOW="$(read_valid_flag)"
[[ "$VALID_NOW" == "1" ]] || fail "VALID=$VALID_NOW want 1"

# Log evidence of v2 sync (not only map state).
grep -E "identity_fresh|applied path-prefix deny list \\+ identity validity|policy bundle unchanged \\(identity TTL refreshed\\)" \
  "$AGENT_LOG" >/dev/null \
  || fail "scenario 2: no identity sync log line in $AGENT_LOG"
pass "scenario 2: ID_EXCEPT_VALID=1 after schema_version 2 sync (bpftool+log)"

lookup_allow_cgroup "$ALLOW_CG_ID" >/dev/null \
  || fail "scenario 3: seeded cgroup_id $ALLOW_CG_ID missing from ID_ALLOW_CGROUP"
pass "scenario 3: ID_ALLOW_CGROUP contains seeded cgroup_id=$ALLOW_CG_ID"

# --- payloads ---
write_payload "$PAYLOAD_TMP"
write_payload "$PAYLOAD_SHM"
write_payload "$PAYLOAD_VTMP"

echo "== scenario 4: seeded cgroup + /tmp/ must ALLOW =="
expect_allow "scenario 4: /tmp/ allow in seeded cgroup" "$CG_BASE/allow" "$PAYLOAD_TMP"

echo "== scenario 5: non-seeded cgroup + /tmp/ must DENY =="
expect_deny "scenario 5: /tmp/ deny in non-seeded cgroup" "$CG_BASE/deny" "$PAYLOAD_TMP"

echo "== scenario 6: seeded cgroup + /dev/shm/ and /var/tmp/ must DENY =="
expect_deny "scenario 6a: /dev/shm/ deny despite seeded cgroup" "$CG_BASE/allow" "$PAYLOAD_SHM"
expect_deny "scenario 6b: /var/tmp/ deny despite seeded cgroup" "$CG_BASE/allow" "$PAYLOAD_VTMP"

echo "== scenario 7: TTL expiry / VALID=0 → seeded /tmp/ must DENY =="
if [[ "$FORCE_VALID_ZERO" == "1" ]]; then
  echo "forcing ID_EXCEPT_VALID=0 via bpftool (NEUROMESH_IDENTITY_TEST_FORCE_VALID_ZERO=1)"
  bpftool map update name ID_EXCEPT_VALID key hex 00 00 00 00 value hex 00 \
    || fail "bpftool map update VALID=0 failed"
else
  echo "stopping bundle stub so expires_at cannot refresh; waiting for TTL (${TEST_TTL_SECS}s) + sync tick"
  kill -TERM "$STUB_PID" 2>/dev/null || true
  wait "$STUB_PID" 2>/dev/null || true
  STUB_PID=""
  # expires_at was issued at stub start ≈ now-elapsed; wait full TTL + sync interval margin.
  sleep $((TEST_TTL_SECS + 35))
fi

if ! wait_valid_flag 0 >/dev/null; then
  # If wall-clock path stalled, still try force for diagnosis then fail closed.
  echo "VALID still non-zero after wait; dumping maps" >&2
  bpftool map dump name ID_EXCEPT_VALID >&2 || true
  fail "scenario 7: ID_EXCEPT_VALID did not become 0"
fi
[[ "$(read_valid_flag)" == "0" ]] || fail "VALID not 0 before deny re-check"
expect_deny "scenario 7: /tmp/ deny after VALID=0 (same seeded cgroup)" "$CG_BASE/allow" "$PAYLOAD_TMP"

echo "ALL ${PASS_COUNT} MANUAL IDENTITY-EXCEPTION CHECKS PASSED"
echo "evidence: agent_log=$AGENT_LOG stub_log=$STUB_LOG allow_cg_id=$ALLOW_CG_ID"
