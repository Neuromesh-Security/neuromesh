#!/usr/bin/env bash
# Phase A: inject the webhook CA into ValidatingWebhookConfiguration.
#
# The in-repo manifest keeps the placeholder REPLACE_WITH_BASE64_CA_BUNDLE
# (the CA is operator-generated; do not commit it). cert-manager is Phase B.
#
# Usage:
#   bash scripts/inject_admission_cabundle.sh /path/to/ca.crt
#   bash scripts/inject_admission_cabundle.sh /path/to/ca.crt - | kubectl apply -f -
#   bash scripts/inject_admission_cabundle.sh /path/to/ca.crt /tmp/vwc.yaml
#
# Helm equivalent (does not use this script):
#   helm upgrade ... --set validatingWebhook.caBundle="$(openssl base64 -A -in ca.crt)"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLACEHOLDER="REPLACE_WITH_BASE64_CA_BUNDLE"
DEFAULT_MANIFEST="$ROOT/deploy/kubernetes/admission/neuromesh-admission-validating-webhook.yaml"

usage() {
  echo "usage: $0 <ca.crt> [output.yaml|-]" >&2
  echo "  omitted/ -  write patched YAML to stdout" >&2
  echo "  output.yaml write patched YAML to that path" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
CA_CRT="$1"
OUT="${2:-}"

command -v python3 >/dev/null || { echo "FAIL: python3 required" >&2; exit 1; }
[[ -s "$CA_CRT" ]] || { echo "FAIL: CA file missing or empty: $CA_CRT" >&2; exit 1; }
[[ -s "$DEFAULT_MANIFEST" ]] || { echo "FAIL: VWC manifest missing: $DEFAULT_MANIFEST" >&2; exit 1; }

if command -v openssl >/dev/null 2>&1; then
  CA_BUNDLE="$(openssl base64 -A -in "$CA_CRT")"
else
  CA_BUNDLE="$(base64 -w0 "$CA_CRT" 2>/dev/null || base64 "$CA_CRT" | tr -d '\n')"
fi
[[ -n "$CA_BUNDLE" ]] || { echo "FAIL: empty caBundle from $CA_CRT" >&2; exit 1; }

# Python replace — base64 can contain '/' which would break sed delimiters.
patched="$(
  python3 - "$DEFAULT_MANIFEST" "$PLACEHOLDER" "$CA_BUNDLE" <<'PY'
import pathlib
import sys

path, needle, bundle = sys.argv[1], sys.argv[2], sys.argv[3]
text = pathlib.Path(path).read_text(encoding="utf-8")
if needle not in text:
    raise SystemExit(f"placeholder {needle} not found in {path}")
out = text.replace(needle, bundle)
if needle in out:
    raise SystemExit("placeholder still present after substitution")
if f"caBundle: {bundle}" not in out:
    raise SystemExit("caBundle was not injected")
sys.stdout.write(out)
PY
)"

if [[ -z "$OUT" || "$OUT" == "-" ]]; then
  printf '%s\n' "$patched"
else
  printf '%s\n' "$patched" >"$OUT"
  echo "wrote $OUT"
fi
