# ADR-001: LSM Active Blocking vs Passive Tracepoint Telemetry

**Status:** Accepted  
**Date:** 2026-07-12  
**Context:** Neuromesh XDR — execution monitoring and enforcement

## Context

Neuromesh must observe process execution (`execve`) and, for high-confidence
threat signatures, **block** execution before a malicious binary runs. Linux
offers two primary eBPF integration surfaces for this problem:

1. **Tracepoints** (`sys_enter_execve`) — passive, always-on telemetry.
2. **LSM hooks** (`bprm_check_security`) — active enforcement in the kernel
   security path, returning `-EPERM` to deny execution.

We need both: observability for SIEM pipelines and synchronous blocking for
ephemeral malware staging paths (`/tmp/`, `/dev/shm/`, `/var/tmp/`).

## Decision

We implement a **dual-hook architecture**:

| Surface | Program | Role |
|---------|---------|------|
| Tracepoint | `neuromesh_exec_hook` | Passive telemetry for all exec events |
| LSM | `neuromesh_lsm_exec_guard` | Active deny for blacklisted path prefixes |

Both hooks emit enriched `SecurityTelemetryEvent` records (pid, ppid, comm,
uid/euid, filename) into a shared RingBuf. User-space applies static rules,
behavioral frequency analysis, and (future) Wasm policies.

### Why LSM for blocking

- **Synchronous enforcement:** LSM runs in the exec security path before the
  binary is loaded. Tracepoints fire on syscall entry but cannot reliably
  prevent execution without additional kernel cooperation.
- **Explicit deny semantics:** Returning `-1` (`-EPERM`) from `bprm_check_security`
  is the supported contract for security modules and eBPF LSM programs.
- **Coexistence with audit/telemetry:** LSM denial and tracepoint observation
  are complementary — blocked events still produce telemetry via the LSM path.

### Why tracepoints remain

- **Universal visibility:** Every `execve` is observed, including executions
  that pass LSM (benign paths, whitelisted binaries).
- **Lower attach friction:** Tracepoints do not require BTF-based LSM attachment
  (though our orchestrator loads both).
- **Health and analytics baseline:** Passive stream feeds the Data Normalizer
  for fork-bomb and spawn-burst detection that static path rules miss.

## Consequences

### Positive

- Active blocking for staging-directory malware without a full kernel module
  rebuild cycle.
- Rich telemetry stream for SIEM, behavioral analytics, and future Wasm policies.
- Clear separation of concerns: Ring 0 enforces + captures, Ring 3 decides.

### Negative / trade-offs

- **Dual attach complexity:** Orchestrator must load tracepoint and LSM programs,
  including BTF for LSM.
- **BPF stack constraints:** Enriched events are written directly into RingBuf
  slots to stay within the 512-byte stack limit.
- **ppid best-effort:** Parent PID is read via `task_struct` offsets without
  full CO-RE; behavior normalizer treats `ppid == 0` as non-actionable.

## Related work

- Context-aware telemetry enrichment (`SecurityTelemetryEvent` lineage fields)
- User-space Data Normalizer (spawn burst / fork-bomb detection)
- Wasm policy engine scaffolding (`wasm_policy.rs`)
