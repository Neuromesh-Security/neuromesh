# Neuromesh Red Team Simulation

Automated chaos test for validating the user-space **RuleEngine** and SIEM JSON alert pipeline.

## Prerequisites

- Linux host with eBPF support (kernel ≥ 5.x recommended)
- Root privileges (required to load eBPF programs and attach tracepoints)
- Rust toolchain (stable + nightly) and `bpf-linker` — same as CI

## Live Fire Test

### Terminal 1 — Build and run the orchestrator

```bash
# Build Ring 0 kernel object
cd apps/agent-ebpf-sensor/ebpf
export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker
cargo +nightly build --package agent-ebpf-sensor-ebpf \
  --target bpfel-unknown-none -Z build-std=core --release

# Build and run user-space orchestrator (requires root)
cd ..
sudo -E cargo +stable run --release
```

The orchestrator prints health metrics every 5 seconds and emits **JSON lines** for CRITICAL_ALERT events.

### Terminal 2 — Run the red-team simulation

```bash
chmod +x scripts/red-team/simulate_tmp_payload.sh
./scripts/red-team/simulate_tmp_payload.sh
```

## Expected Behavior

| Phase | Action | Orchestrator output |
|---|---|---|
| 1 | `ls`, `cat` (benign) | **Silent** — whitelist suppression |
| 2–3 | Execute `/tmp/evil_payload.bin` | **JSON alert** with `severity: CRITICAL_ALERT` |
| 4 | Script cleanup | No further alerts |

### Sample CRITICAL_ALERT JSON

```json
{
  "timestamp": "2026-07-11T20:15:42.123456789+00:00",
  "severity": "CRITICAL_ALERT",
  "rule_id": "NEUROMESH-EXEC-BLACKLIST-PATH",
  "rule_name": "Execution from ephemeral malware staging directory",
  "pid": 4242,
  "uid": 1000,
  "binary_path": "/tmp/evil_payload.bin",
  "matched_pattern": "/tmp/"
}
```
