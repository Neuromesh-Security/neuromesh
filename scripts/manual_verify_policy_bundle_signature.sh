#!/usr/bin/env bash
# Manual verification: Cosign-compatible policy-bundle signature (fail-closed).
#
# Addresses external Rego/policy-bundle security review P0: bearer auth alone is
# not content integrity. Agent must verify X-Neuromesh-Policy-Bundle-Signature
# over exact body bytes before apply_deny_entries / apply_identity_validity.
#
# Paste-back sequence (Linux droplet / BPF-LSM host with Cosign attestation already
# wired for agent startup - same preconditions as manual_verify_identity_exception.sh):
#
#   cd /path/to/neuromesh
#   export AGENT_BIN=./target/release/agent-ebpf-sensor
#   sudo -E bash scripts/manual_verify_policy_bundle_signature.sh
#
# Cases:
#   1) Valid signature  -> agent sync applies
#   2) Corrupt signature -> signature_invalid
#   3) Missing header    -> signature_missing
#   4) Tampered body     -> signature_invalid
#
# Requires: root, python3 (+ cryptography), curl, agent binary, Cosign attestation for agent start.
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
"""GET /v1/policy-bundle stub with Cosign-compatible Ed25519 detached signatures."""
from __future__ import annotations
import base64, hashlib, json, os, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.serialization import load_pem_private_key

TOKEN = os.environ["NEUROMESH_POLICY_BUNDLE_TOKEN"]
PORT = int(os.environ.get("NEUROMESH_SIG_TEST_PE_PORT", "18081"))
MODE = os.environ.get("NEUROMESH_SIG_STUB_MODE", "valid")  # valid|corrupt|missing|tamper
PRIV_PATH = os.environ["NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH"]

with open(PRIV_PATH, "rb") as f:
    PRIV = load_pem_private_key(f.read(), password=None)

def bundle_obj(tamper: bool = False):
    now = int(time.time())
    prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"]
    if tamper:
        prefixes = prefixes + ["/evil/"]
    return {
        "schema_version": 2,
        "version": "sha256:" + hashlib.sha256("|".join(prefixes).encode()).hexdigest(),
        "deny_path_prefixes": prefixes,
        "identity_allow_exceptions": {
            "scope_path_prefix": "/tmp/",
            "spiffe_ids": [
                "spiffe://neuromesh.security/ns/default/sa/agent-ebpf-sensor",
            ],
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 90)),
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
        signed_obj = bundle_obj(tamper=False)
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
  export NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH="$PUB_KEY"
  unset NEUROMESH_POLICY_BUNDLE_TOKEN_FILE || true
  : >"$AGENT_LOG"
  "$AGENT_BIN" >>"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  sleep 2
  kill -0 "$AGENT_PID" || fail "agent failed to start; see $AGENT_LOG"
}

wait_log() {
  local pattern="$1"
  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    if grep -Eq "$pattern" "$AGENT_LOG" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "---- agent log (tail) ----" >&2
  tail -n 80 "$AGENT_LOG" >&2 || true
  return 1
}

echo "== scenario 1: valid signature -> sync applies =="
start_stub valid
curl -sf -H "Authorization: Bearer ${BUNDLE_TOKEN}" \
  -D "${TEST_ROOT}/headers.valid" \
  "http://127.0.0.1:${PE_PORT}/v1/policy-bundle" -o "${TEST_ROOT}/body.valid" \
  || fail "stub GET failed"
grep -qi 'X-Neuromesh-Policy-Bundle-Signature:' "${TEST_ROOT}/headers.valid" \
  || fail "stub missing signature header"
start_agent
wait_log 'applied path-prefix deny list \+ identity validity|policy bundle unchanged \(identity TTL refreshed\)' \
  || fail "agent did not apply valid signed bundle"
pass "scenario 1: valid signature applied"

echo "== scenario 2: corrupt signature -> signature_invalid =="
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

echo
echo "ALL PASS ($PASS_COUNT). evidence: agent_log=$AGENT_LOG stub_log=$STUB_LOG keys=$KEY_DIR"
