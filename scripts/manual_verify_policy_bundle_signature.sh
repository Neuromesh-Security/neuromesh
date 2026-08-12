#!/usr/bin/env bash
# Manual verification: Cosign-compatible policy-bundle signature + T-PB-04 temporal binding.
#
# Issue (T-PB-04 / Grok audit #3) — follow-on to Issue #108:
# Signature proves integrity; temporal fields inside the signed body bound replay.
# Agent verifies X-Neuromesh-Policy-Bundle-Signature, then not_before/not_after,
# BEFORE apply_deny_entries / apply_identity_validity.
#
# PE production behavior (documented, intentional): zt-policy-engine refuses to
# boot without NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH. This script uses a PE
# *stub* that signs with the same Cosign-compatible Ed25519 wire format so the
# agent verify path can be exercised without a full SPIFFE stack.
#
# Paste-back sequence (Linux droplet / BPF-LSM host with Cosign attestation already
# wired for agent startup — same preconditions as manual_verify_identity_exception.sh):
#
#   cd /path/to/neuromesh
#   cargo build -p agent-ebpf-sensor --features orchestrator --release
#   export AGENT_BIN=./target/release/agent-ebpf-sensor
#   sudo -E bash scripts/manual_verify_policy_bundle_signature.sh
#
# Cases (all must PASS; paste full script output + agent_log paths back to PR):
#   1) Valid signature + fresh temporal → agent sync applies
#   2) Corrupt signature → REJECTED, reason=signature_invalid; no apply
#   3) Missing header    → REJECTED, reason=signature_missing; no apply
#   4) Tampered body     → REJECTED, reason=signature_invalid; no apply
#   5) Capture fresh body+sig → apply OK; wait past short window; stub mode
#      `replay` serves EXACT captured bytes+sig → agent logs bundle_expired; no apply
#   6) Skew: not_before slightly future within ±5s → still accepted
#
# Fail-closed contract: sync failure retains last-known-good deny (bootstrap or
# prior good sync). Identity VALID must not be refreshed from a rejected body.
#
# Requires: root, python3 (+ cryptography), curl, agent binary, Cosign attestation
# for agent start. See apps/zt-policy-engine/README.md + SECURITY.md + docs/threat-model.md.
set -euo pipefail

PIN_ROOT="${NEUROMESH_BPF_PIN_ROOT:-/sys/fs/bpf/neuromesh}"
AGENT_BIN="${AGENT_BIN:-./target/release/agent-ebpf-sensor}"
TEST_ROOT="${NEUROMESH_SIG_TEST_ROOT:-/opt/neuromesh-test/policy-bundle-sig}"
BUNDLE_TOKEN="${NEUROMESH_POLICY_BUNDLE_TOKEN:-policy-bundle-sig-manual-token}"
PE_PORT="${NEUROMESH_SIG_TEST_PE_PORT:-18081}"
AGENT_LOG="${NEUROMESH_SIG_TEST_AGENT_LOG:-${TEST_ROOT}/agent.log}"
STUB_LOG="${TEST_ROOT}/stub.log"
KEY_DIR="${TEST_ROOT}/keys"
PRIV_KEY="${KEY_DIR}/bundle_signing.pem"
PUB_KEY="${KEY_DIR}/bundle.pub"
# Short window for live anti-replay (PE default is 300s).
SHORT_VALIDITY_SECS="${NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS:-15}"

PASS_COUNT=0
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }

echo "== preflight =="
test "$(id -u)" -eq 0 || fail "must run as root (agent BPF pin)"
test -x "$AGENT_BIN" || fail "AGENT_BIN not executable: $AGENT_BIN"
command -v python3 >/dev/null || fail "python3 required"
command -v curl >/dev/null || fail "curl required"
python3 -c "import cryptography" >/dev/null 2>&1 || fail "python3 cryptography package required"
mkdir -p "$TEST_ROOT" "$KEY_DIR" "$PIN_ROOT"
mount | grep -Eq 'type bpf|bpffs' || mount -t bpf bpf /sys/fs/bpf || true

echo "== generate Ed25519 PKCS#8 keypair =="
export KEY_DIR
python3 - <<'PY'
import os, pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
key_dir = pathlib.Path(os.environ["KEY_DIR"])
key_dir.mkdir(parents=True, exist_ok=True)
priv = Ed25519PrivateKey.generate()
(key_dir / "bundle_signing.pem").write_bytes(
    priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)
(key_dir / "bundle.pub").write_bytes(
    priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)
print("keys ready in", key_dir)
PY
test -f "$PRIV_KEY" && test -f "$PUB_KEY" || fail "keypair missing"

STUB_PY="${TEST_ROOT}/signed_bundle_stub.py"
cat >"$STUB_PY" <<'PY'
#!/usr/bin/env python3
"""GET /v1/policy-bundle stub with Cosign-compatible Ed25519 + schema 3 temporal."""
from __future__ import annotations
import base64, hashlib, json, os, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.serialization import load_pem_private_key

TOKEN = os.environ["NEUROMESH_POLICY_BUNDLE_TOKEN"]
PORT = int(os.environ.get("NEUROMESH_SIG_TEST_PE_PORT", "18081"))
# valid|corrupt|missing|tamper|replay|skew
MODE = os.environ.get("NEUROMESH_SIG_STUB_MODE", "valid")
PRIV_PATH = os.environ["NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH"]
VALIDITY = int(os.environ.get("NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS", "15"))
CAPTURE_BODY = os.environ.get("NEUROMESH_SIG_CAPTURE_BODY", "")
CAPTURE_SIG = os.environ.get("NEUROMESH_SIG_CAPTURE_SIG", "")
SKEW_FUTURE_SECS = int(os.environ.get("NEUROMESH_SIG_STUB_SKEW_FUTURE_SECS", "3"))

with open(PRIV_PATH, "rb") as f:
    PRIV = load_pem_private_key(f.read(), password=None)

def rfc3339(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

def bundle_obj(tamper: bool = False, skew_future: bool = False):
    now = int(time.time())
    if skew_future:
        # not_before slightly in the future but within agent ±5s skew.
        nb = now + SKEW_FUTURE_SECS
    else:
        nb = now
    prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"]
    if tamper:
        prefixes = prefixes + ["/evil/"]
    return {
        "schema_version": 3,
        "version": "sha256:" + hashlib.sha256("|".join(prefixes).encode()).hexdigest(),
        "not_before": rfc3339(nb),
        "not_after": rfc3339(nb + VALIDITY),
        "deny_path_prefixes": prefixes,
        "identity_allow_exceptions": {
            "scope_path_prefix": "/tmp/",
            "spiffe_ids": [
                "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
            ],
            "issued_at": rfc3339(now),
            "expires_at": rfc3339(now + 90),
        },
    }

class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[stub]", fmt % args)

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

        if MODE == "replay":
            if not CAPTURE_BODY or not CAPTURE_SIG:
                self.send_error(500, "replay capture missing")
                return
            body = open(CAPTURE_BODY, "rb").read()
            sig = open(CAPTURE_SIG, "r", encoding="utf-8").read().strip()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Neuromesh-Policy-Bundle-Signature", sig)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        signed_obj = bundle_obj(tamper=False, skew_future=(MODE == "skew"))
        signed_body = (json.dumps(signed_obj, separators=(",", ":")) + "\n").encode()
        sig = base64.b64encode(PRIV.sign(signed_body)).decode()
        if MODE == "tamper":
            body = (json.dumps(bundle_obj(tamper=True), separators=(",", ":")) + "\n").encode()
        else:
            body = signed_body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if MODE == "corrupt":
            self.send_header("X-Neuromesh-Policy-Bundle-Signature", "YWJjZGVmZ2hpams=")
        elif MODE == "missing":
            pass
        else:
            self.send_header("X-Neuromesh-Policy-Bundle-Signature", sig)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY
chmod +x "$STUB_PY"

STUB_PID=""
AGENT_PID=""
cleanup() {
  if [[ -n "${AGENT_PID:-}" ]]; then kill -TERM "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n "${STUB_PID:-}" ]]; then kill -TERM "$STUB_PID" 2>/dev/null || true; wait "$STUB_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

start_stub() {
  local mode="$1"
  if [[ -n "${STUB_PID:-}" ]]; then kill -TERM "$STUB_PID" 2>/dev/null || true; wait "$STUB_PID" 2>/dev/null || true; STUB_PID=""; fi
  export NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN"
  export NEUROMESH_SIG_TEST_PE_PORT="$PE_PORT"
  export NEUROMESH_SIG_STUB_MODE="$mode"
  export NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH="$PRIV_KEY"
  export NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS="$SHORT_VALIDITY_SECS"
  : >"$STUB_LOG"
  python3 "$STUB_PY" >>"$STUB_LOG" 2>&1 &
  STUB_PID=$!
  sleep 0.5
  kill -0 "$STUB_PID" || fail "stub failed to start (mode=$mode) see $STUB_LOG"
}

start_agent() {
  if [[ -n "${AGENT_PID:-}" ]]; then kill -TERM "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; AGENT_PID=""; fi
  export NEUROMESH_ZT_POLICY_ENGINE_URL="http://127.0.0.1:${PE_PORT}"
  export NEUROMESH_POLICY_BUNDLE_TOKEN="$BUNDLE_TOKEN"
  # Verification-side pubkey (NOT the signing private key). Absolute path required.
  export NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH="$PUB_KEY"
  unset NEUROMESH_POLICY_BUNDLE_TOKEN_FILE || true
  export NEUROMESH_BPF_PIN_ROOT="$PIN_ROOT"
  # Integrity exit would abort mid-test if pins are manipulated elsewhere.
  export NEUROMESH_INTEGRITY_EXIT_ON_FAILURE="${NEUROMESH_INTEGRITY_EXIT_ON_FAILURE:-false}"
  # Sync success/failure lines are tracing::info!/warn! — EnvFilter::from_default_env()
  # without RUST_LOG is ERROR-only (same harness bug class as identity_exception.sh).
  export RUST_LOG="${RUST_LOG:-neuromesh=info,neuromesh::policy_sync=info,agent_ebpf_sensor=info}"
  : >"$AGENT_LOG"
  echo "agent env: PE_URL=${NEUROMESH_ZT_POLICY_ENGINE_URL} PUBLIC_KEY=${NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH} RUST_LOG=${RUST_LOG}"
  test -f "$NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH" \
    || fail "agent pubkey missing at $NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH"
  "$AGENT_BIN" >>"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  # Attestation + BPF load often exceeds 2s — wait for process + pin, not a fixed sleep.
  local i
  for i in $(seq 1 60); do
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
      echo "---- agent log ----" >&2
      cat "$AGENT_LOG" >&2 || true
      fail "agent died during startup"
    fi
    if test -f "$PIN_ROOT/neuromesh_lsm_exec_guard_link" && test -f "$PIN_ROOT/PATH_DENY_LIST"; then
      break
    fi
    sleep 1
  done
  kill -0 "$AGENT_PID" || fail "agent failed to start; see $AGENT_LOG"
  test -f "$PIN_ROOT/PATH_DENY_LIST" || fail "PATH_DENY_LIST pin missing; see $AGENT_LOG"
}

dump_diag() {
  echo "---- diag: agent log (full grep) ----" >&2
  grep -Eni 'policy_sync|signature|policy-bundle|bundle_expired|bundle_not_yet|temporal|applied path-prefix|last-known-good|STALE|sync' \
    "$AGENT_LOG" 2>/dev/null >&2 || echo "(no matching lines in $AGENT_LOG)" >&2
  echo "---- diag: agent log (tail 120) ----" >&2
  tail -n 120 "$AGENT_LOG" >&2 || true
  echo "---- diag: stub log ----" >&2
  cat "$STUB_LOG" >&2 || true
  echo "---- diag: listen check ----" >&2
  ss -ltnp 2>/dev/null | grep -E ":${PE_PORT}\\b" >&2 || netstat -ltn 2>/dev/null | grep -E ":${PE_PORT}\\b" >&2 || true
}

wait_log() {
  local pattern="$1"
  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    if grep -Eq "$pattern" "$AGENT_LOG" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
      echo "agent died while waiting for: $pattern" >&2
      dump_diag
      return 1
    fi
    sleep 1
  done
  dump_diag
  return 1
}

echo "== scenario 1: valid signature + fresh temporal -> sync applies =="
start_stub valid
# Confirm stub listen + signed response BEFORE agent (port/wiring class).
ss -ltn 2>/dev/null | grep -qE ":${PE_PORT}\\b" \
  || netstat -ltn 2>/dev/null | grep -qE ":${PE_PORT}\\b" \
  || fail "stub not listening on 127.0.0.1:${PE_PORT}"
curl -sf -H "Authorization: Bearer ${BUNDLE_TOKEN}" \
  -D "${TEST_ROOT}/headers.valid" \
  "http://127.0.0.1:${PE_PORT}/v1/policy-bundle" -o "${TEST_ROOT}/body.valid" \
  || fail "stub GET failed"
grep -qi 'X-Neuromesh-Policy-Bundle-Signature:' "${TEST_ROOT}/headers.valid" \
  || fail "stub missing signature header"
# Prove stub signature verifies with the generated pubkey (harness crypto, not agent).
export NEUROMESH_SIG_TEST_ROOT="$TEST_ROOT"
python3 - <<'PY' || fail "stub signature does not verify / temporal fields missing"
import base64, json, os, pathlib
from cryptography.hazmat.primitives.serialization import load_pem_public_key
test_root = pathlib.Path(os.environ["NEUROMESH_SIG_TEST_ROOT"])
body = (test_root / "body.valid").read_bytes()
doc = json.loads(body)
assert doc.get("schema_version") == 3, doc
assert doc.get("not_before") and doc.get("not_after"), doc
pub = load_pem_public_key((test_root / "keys" / "bundle.pub").read_bytes())
sig_b64 = None
for line in (test_root / "headers.valid").read_text().splitlines():
    if line.lower().startswith("x-neuromesh-policy-bundle-signature:"):
        sig_b64 = line.split(":", 1)[1].strip()
        break
assert sig_b64, "signature header missing"
pub.verify(base64.b64decode(sig_b64), body)
print("stub Cosign-compatible Ed25519 signature OK over exact schema-3 body bytes")
PY
start_agent
wait_log 'applied path-prefix deny list \+ identity validity|policy bundle unchanged \(identity TTL refreshed\)' \
  || fail "agent did not apply valid signed bundle"
pass "scenario 1: valid signature + temporal applied"

echo "== scenario 2: corrupt signature -> signature_invalid (no apply; LKG retained) =="
start_stub corrupt
kill -TERM "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
: >"$AGENT_LOG"
start_agent
wait_log 'signature_invalid' || fail "expected signature_invalid in agent log"
if grep -Eq 'applied path-prefix deny list \+ identity validity' "$AGENT_LOG"; then
  fail "must not apply on corrupt signature"
fi
# Rejected sync must retain last-known-good framing (same class as auth failure).
grep -Eq 'retaining last-known-good|signature_invalid' "$AGENT_LOG" \
  || fail "expected last-known-good / signature_invalid sync-failure framing"
pass "scenario 2: corrupt signature rejected (signature_invalid)"

echo "== scenario 3: missing signature header -> signature_missing =="
start_stub missing
kill -TERM "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
: >"$AGENT_LOG"
start_agent
wait_log 'signature_missing' || fail "expected signature_missing in agent log"
if grep -Eq 'applied path-prefix deny list \+ identity validity' "$AGENT_LOG"; then
  fail "must not apply on missing signature"
fi
pass "scenario 3: missing header rejected (signature_missing)"

echo "== scenario 4: tampered body -> signature_invalid =="
start_stub tamper
kill -TERM "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
: >"$AGENT_LOG"
start_agent
wait_log 'signature_invalid' || fail "expected signature_invalid for tampered body"
if grep -Eq 'applied path-prefix deny list \+ identity validity' "$AGENT_LOG"; then
  fail "must not apply on tampered body"
fi
pass "scenario 4: tampered body rejected (signature_invalid)"

echo "== scenario 5: capture fresh → apply OK; wait past window → replay exact bytes → bundle_expired =="
start_stub valid
# Capture EXACT body + signature while fresh (before agent so we own the bytes).
curl -sf -H "Authorization: Bearer ${BUNDLE_TOKEN}" \
  -D "${TEST_ROOT}/headers.capture" \
  "http://127.0.0.1:${PE_PORT}/v1/policy-bundle" -o "${TEST_ROOT}/body.capture" \
  || fail "capture GET failed"
python3 - <<'PY' || fail "extract capture signature"
import pathlib, os
test_root = pathlib.Path(os.environ["NEUROMESH_SIG_TEST_ROOT"])
sig = None
for line in (test_root / "headers.capture").read_text().splitlines():
    if line.lower().startswith("x-neuromesh-policy-bundle-signature:"):
        sig = line.split(":", 1)[1].strip()
        break
assert sig, "missing signature on capture"
(test_root / "sig.capture").write_text(sig + "\n")
print("captured body+sig for replay")
PY
export NEUROMESH_SIG_CAPTURE_BODY="${TEST_ROOT}/body.capture"
export NEUROMESH_SIG_CAPTURE_SIG="${TEST_ROOT}/sig.capture"
kill -TERM "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
: >"$AGENT_LOG"
start_agent
wait_log 'applied path-prefix deny list \+ identity validity|policy bundle unchanged \(identity TTL refreshed\)' \
  || fail "agent did not apply freshly captured signed bundle"
pass "scenario 5a: fresh capture applied"

echo "waiting $((SHORT_VALIDITY_SECS + 6))s past short validity window (${SHORT_VALIDITY_SECS}s + skew)..."
sleep $((SHORT_VALIDITY_SECS + 6))
# Replay exact captured bytes+sig (signature still valid; temporal must fail).
start_stub replay
: >"$AGENT_LOG"
# Agent still running — wait for next sync tick (POLICY_SYNC_INTERVAL=30s).
wait_log 'bundle_expired' || fail "expected bundle_expired on replay after window"
if grep -Eq 'applied path-prefix deny list \+ identity validity' "$AGENT_LOG"; then
  fail "must not apply on expired replayed bundle"
fi
grep -Eq 'retaining last-known-good|bundle_expired' "$AGENT_LOG" \
  || fail "expected LKG framing with bundle_expired"
pass "scenario 5b: replay past window rejected (bundle_expired, no apply)"

echo "== scenario 6: skew — not_before slightly future within ±5s still accepted =="
start_stub skew
kill -TERM "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""
: >"$AGENT_LOG"
start_agent
wait_log 'applied path-prefix deny list \+ identity validity|policy bundle unchanged \(identity TTL refreshed\)' \
  || fail "agent should accept not_before within clock skew"
pass "scenario 6: skew-tolerant not_before accepted"

echo
echo "ALL PASS ($PASS_COUNT). evidence: agent_log=$AGENT_LOG stub_log=$STUB_LOG keys=$KEY_DIR"
echo "Paste this full script output + agent_log excerpts back to the PR before merge."
