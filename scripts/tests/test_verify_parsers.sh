#!/usr/bin/env bash
# Unit tests for pin ABI bpftool -j dump parsers (no BPF, no extra deps).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PARSER="$ROOT/scripts/pin_abi_verify_parsers.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

test -f "$PARSER" || fail "missing $PARSER"

# --- non-BTF raw arrays (hex strings) ---
cat >"$TMP/count_raw.json" <<'EOF'
[{"key": ["0x00", "0x00", "0x00", "0x00"], "value": ["0x04", "0x00", "0x00", "0x00"]}]
EOF
got="$(python3 "$PARSER" count0 "$TMP/count_raw.json")"
[[ "$got" == "4" ]] || fail "raw count0 expected 4 got $got"
pass "non-BTF raw arrays (count0=4)"

# --- BTF formatted (decoded ints + struct) ---
cat >"$TMP/count_btf.json" <<'EOF'
[{"key": 0, "value": 2, "formatted": {"key": 0, "value": 2}}]
EOF
got="$(python3 "$PARSER" count0 "$TMP/count_btf.json")"
[[ "$got" == "2" ]] || fail "BTF count0 expected 2 got $got"
pass "BTF formatted (count0=2)"

# --- zero count must fail ---
cat >"$TMP/count_zero.json" <<'EOF'
[{"key": ["0x00", "0x00", "0x00", "0x00"], "value": ["0x00", "0x00", "0x00", "0x00"]}]
EOF
# count0 itself returns 0; f3_continuity rejects zero
got="$(python3 "$PARSER" count0 "$TMP/count_zero.json")"
[[ "$got" == "0" ]] || fail "zero count parse expected 0 got $got"
cat >"$TMP/list_one.json" <<'EOF'
[{"key": ["0x00", "0x00", "0x00", "0x00"], "value": ["0x05", "0x00", "0x00", "0x00", "0x2f", "0x74", "0x6d", "0x70", "0x2f", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00"]}]
EOF
if python3 "$PARSER" f3_continuity "$TMP/list_one.json" "$TMP/count_zero.json" "$TMP/list_one.json" "$TMP/count_zero.json" 2>/dev/null; then
  fail "zero count should fail f3_continuity"
fi
pass "zero count rejected by f3_continuity"

# --- missing key 0 ---
cat >"$TMP/count_missing.json" <<'EOF'
[{"key": ["0x01", "0x00", "0x00", "0x00"], "value": ["0x04", "0x00", "0x00", "0x00"]}]
EOF
if python3 "$PARSER" count0 "$TMP/count_missing.json" 2>/dev/null; then
  fail "missing key 0 should exit non-zero"
fi
pass "missing key 0 rejected"

# --- unknown shape ---
cat >"$TMP/unknown.json" <<'EOF'
[{"weird": true}]
EOF
if python3 "$PARSER" count0 "$TMP/unknown.json" 2>"$TMP/unknown.err"; then
  fail "unknown shape should exit non-zero"
fi
grep -q "unknown bpftool map dump shape" "$TMP/unknown.err" || fail "unknown shape missing error label"
grep -q "weird" "$TMP/unknown.err" || fail "unknown shape must print raw text"
pass "unknown shape exits 1 and prints raw text"

# --- F3 continuity happy path: legacy 20B → new 36B same identity ---
# legacy: len=5 "/tmp/" + 11 zero pad = 20B value
# new: len=5 "/tmp/" + 27 zero pad = 36B value
python3 - <<'PY' >"$TMP/legacy_list.json"
import json
val20 = [0x05,0,0,0, 0x2f,0x74,0x6d,0x70,0x2f] + [0]*11
assert len(val20)==20
print(json.dumps([{"key":["0x00","0x00","0x00","0x00"],"value":[f"0x{b:02x}" for b in val20]}]))
PY
python3 - <<'PY' >"$TMP/new_list.json"
import json
val36 = [0x05,0,0,0, 0x2f,0x74,0x6d,0x70,0x2f] + [0]*27
assert len(val36)==36
print(json.dumps([{"key":["0x00","0x00","0x00","0x00"],"value":[f"0x{b:02x}" for b in val36]}]))
PY
cat >"$TMP/count_one.json" <<'EOF'
[{"key": ["0x00", "0x00", "0x00", "0x00"], "value": ["0x01", "0x00", "0x00", "0x00"]}]
EOF
python3 "$PARSER" f3_continuity \
  "$TMP/legacy_list.json" "$TMP/count_one.json" \
  "$TMP/new_list.json" "$TMP/count_one.json" >/dev/null
pass "F3 continuity legacy20→new36"

echo "ALL PARSER TESTS PASSED"
