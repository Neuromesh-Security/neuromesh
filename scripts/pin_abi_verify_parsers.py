#!/usr/bin/env python3
"""Parsers for bpftool -j map dump used by pin ABI live verify (no BPF deps)."""
from __future__ import annotations

import json
import sys
from typing import Any


def _hex_byte(tok: str) -> int:
    s = tok.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    # bpftool print_hex_data_json emits "0xNN"; plain hex without prefix is also accepted
    if len(s) <= 2 and all(c in "0123456789abcdef" for c in s):
        return int(s, 16)
    raise ValueError(f"not a hex byte token: {tok!r}")


def bytes_from_bpftool_field(field: Any) -> bytes:
    """Decode a bpftool JSON key/value field into raw bytes.

    Supported shapes:
      - list of hex strings: ["0x04", "0x00", ...]  (non-BTF / raw)
      - list of ints: [4, 0, 0, 0]
      - int (scalar key/value when BTF collapses a small integer)
    """
    if isinstance(field, list):
        out = bytearray()
        for item in field:
            if isinstance(item, int):
                if not 0 <= item <= 255:
                    raise ValueError(f"byte out of range: {item}")
                out.append(item)
            elif isinstance(item, str):
                out.append(_hex_byte(item))
            else:
                raise ValueError(f"unknown byte list element type: {type(item).__name__}")
        return bytes(out)
    if isinstance(field, int):
        if field < 0:
            raise ValueError(f"negative scalar: {field}")
        # little-endian u32 when fits; else minimal unsigned width
        if field <= 0xFFFFFFFF:
            return field.to_bytes(4, "little")
        raise ValueError(f"scalar too large for u32: {field}")
    if isinstance(field, str):
        return bytes([_hex_byte(field)])
    raise ValueError(f"unsupported field type: {type(field).__name__}")


def _entry_from_formatted(obj: dict) -> tuple[bytes, bytes] | None:
    """Try BTF `formatted` object: {key: ..., value: ...} with decoded fields."""
    if "key" not in obj or "value" not in obj:
        return None
    key_f = obj["key"]
    val_f = obj["value"]
    # formatted key may be int or nested; value may be int or struct dict
    if isinstance(key_f, int):
        key_b = key_f.to_bytes(4, "little")
    elif isinstance(key_f, (list, str)):
        key_b = bytes_from_bpftool_field(key_f)
    else:
        return None
    if isinstance(val_f, int):
        val_b = val_f.to_bytes(4, "little")
    elif isinstance(val_f, list):
        val_b = bytes_from_bpftool_field(val_f)
    elif isinstance(val_f, dict):
        # PathDenyEntry-like: {len: N, bytes: [...]}
        if "len" in val_f and "bytes" in val_f:
            ln = int(val_f["len"])
            raw = bytes_from_bpftool_field(val_f["bytes"])
            # reconstruct packed entry: u32 len + key bytes (pad handled by caller size)
            val_b = ln.to_bytes(4, "little") + raw
        else:
            return None
    else:
        return None
    return key_b, val_b


def parse_map_dump_entries(text: str) -> list[tuple[bytes, bytes]]:
    """Parse bpftool -j map dump JSON into (key_bytes, value_bytes) pairs.

    Supports:
      - raw: {"key": ["0x..", ...], "value": ["0x..", ...]}
      - raw + BTF: same plus "formatted": {...}
      - BTF-only style where top-level key/value are already decoded ints/structs
    On unknown shape: prints raw text to stderr and raises SystemExit(1).
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"unknown bpftool map dump shape (JSON decode): {e}\n")
        sys.stderr.write(text)
        if not text.endswith("\n"):
            sys.stderr.write("\n")
        raise SystemExit(1)

    if not isinstance(data, list):
        sys.stderr.write("unknown bpftool map dump shape: top-level is not a list\n")
        sys.stderr.write(text)
        if not text.endswith("\n"):
            sys.stderr.write("\n")
        raise SystemExit(1)

    out: list[tuple[bytes, bytes]] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            sys.stderr.write(f"unknown bpftool map dump shape: entry[{i}] not an object\n")
            sys.stderr.write(text)
            if not text.endswith("\n"):
                sys.stderr.write("\n")
            raise SystemExit(1)
        try:
            if isinstance(item.get("key"), list) and isinstance(item.get("value"), list):
                key_b = bytes_from_bpftool_field(item["key"])
                val_b = bytes_from_bpftool_field(item["value"])
                out.append((key_b, val_b))
                continue
            # Prefer raw arrays; else formatted; else BTF-decoded top-level
            if "formatted" in item and isinstance(item["formatted"], dict):
                parsed = _entry_from_formatted(item["formatted"])
                if parsed is not None:
                    out.append(parsed)
                    continue
            parsed = _entry_from_formatted(item)
            if parsed is not None:
                out.append(parsed)
                continue
        except ValueError as e:
            sys.stderr.write(f"unknown bpftool map dump shape: entry[{i}]: {e}\n")
            sys.stderr.write(text)
            if not text.endswith("\n"):
                sys.stderr.write("\n")
            raise SystemExit(1)
        sys.stderr.write(f"unknown bpftool map dump shape: entry[{i}] keys={sorted(item.keys())}\n")
        sys.stderr.write(text)
        if not text.endswith("\n"):
            sys.stderr.write("\n")
        raise SystemExit(1)
    return out


def parse_count0(text: str) -> int:
    """Return PATH_DENY_COUNT[0] from bpftool -j map dump. Exit 1 on unknown/empty."""
    entries = parse_map_dump_entries(text)
    for key_b, val_b in entries:
        if len(key_b) >= 4 and int.from_bytes(key_b[:4], "little") == 0:
            if len(val_b) < 4:
                sys.stderr.write("COUNT value truncated\n")
                sys.stderr.write(text)
                raise SystemExit(1)
            return int.from_bytes(val_b[:4], "little")
    sys.stderr.write("F3: PATH_DENY_COUNT missing key 0\n")
    sys.stderr.write(text)
    raise SystemExit(1)


def deny_entry_identity(value: bytes) -> tuple[int, bytes]:
    """(len, significant key bytes) from a packed LIST value (20B legacy or 36B current)."""
    if len(value) < 4:
        raise ValueError("LIST value truncated")
    ln = int.from_bytes(value[:4], "little")
    key = value[4:]
    if ln <= 0 or ln > len(key):
        raise ValueError(f"invalid deny len={ln} key_len={len(key)}")
    return ln, key[:ln]


def parse_list_identities(text: str) -> set[tuple[int, bytes]]:
    """Set of (len, significant bytes) for non-empty LIST slots (skip zero-len)."""
    entries = parse_map_dump_entries(text)
    ids: set[tuple[int, bytes]] = set()
    for _key_b, val_b in entries:
        if len(val_b) < 4:
            continue
        ln = int.from_bytes(val_b[:4], "little")
        if ln == 0:
            continue
        ids.add(deny_entry_identity(val_b))
    return ids


def assert_f3_continuity(legacy_list_json: str, legacy_count_json: str,
                         new_list_json: str, new_count_json: str) -> None:
    """Assert every legacy LIST identity is present in new LIST; sets equal; COUNT match."""
    legacy_ids = parse_list_identities(legacy_list_json)
    new_ids = parse_list_identities(new_list_json)
    legacy_count = parse_count0(legacy_count_json)
    new_count = parse_count0(new_count_json)

    if legacy_count == 0:
        sys.stderr.write("F3: legacy PATH_DENY_COUNT[0] == 0\n")
        raise SystemExit(1)
    if new_count == 0:
        sys.stderr.write("F3: new PATH_DENY_COUNT[0] == 0\n")
        raise SystemExit(1)
    if legacy_count != new_count:
        sys.stderr.write(
            f"F3: COUNT mismatch legacy={legacy_count} new={new_count}\n"
        )
        raise SystemExit(1)
    if not legacy_ids:
        sys.stderr.write("F3: legacy LIST produced zero non-empty identities\n")
        raise SystemExit(1)
    missing = legacy_ids - new_ids
    if missing:
        sys.stderr.write(f"F3: legacy entries missing from new LIST: {missing!r}\n")
        raise SystemExit(1)
    extra = new_ids - legacy_ids
    if extra:
        sys.stderr.write(
            f"F3: new LIST has entries not in legacy (PE must not run): {extra!r}\n"
        )
        raise SystemExit(1)
    if len(legacy_ids) != legacy_count:
        sys.stderr.write(
            f"F3: legacy identity count {len(legacy_ids)} != COUNT[0] {legacy_count}\n"
        )
        raise SystemExit(1)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write(
            "usage: pin_abi_verify_parsers.py "
            "{count0|list_ids|f3_continuity} ...\n"
        )
        return 2
    cmd = argv[1]
    if cmd == "count0":
        text = Path_read(argv[2]) if len(argv) > 2 else sys.stdin.read()
        print(parse_count0(text))
        return 0
    if cmd == "list_ids":
        text = Path_read(argv[2]) if len(argv) > 2 else sys.stdin.read()
        for ln, key in sorted(parse_list_identities(text)):
            print(f"{ln}:{key.hex()}")
        return 0
    if cmd == "f3_continuity":
        if len(argv) != 6:
            sys.stderr.write(
                "usage: ... f3_continuity LEGACY_LIST LEGACY_COUNT NEW_LIST NEW_COUNT\n"
            )
            return 2
        assert_f3_continuity(
            Path_read(argv[2]),
            Path_read(argv[3]),
            Path_read(argv[4]),
            Path_read(argv[5]),
        )
        print("F3 continuity OK")
        return 0
    sys.stderr.write(f"unknown command: {cmd}\n")
    return 2


def Path_read(p: str) -> str:
    from pathlib import Path

    return Path(p).read_text(encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
