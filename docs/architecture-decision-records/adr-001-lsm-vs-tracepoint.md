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
| Tracepoint | `nm_proc_events` + `nm_execveat` (C) | Passive telemetry for all `execve` / `execveat` (`fexecve`) events |
| LSM | `nm_lsm_bprm` (Rust) | Active deny for blacklisted path prefixes |

Visibility events go to `PROCESS_EVENTS`. LSM **blocked** events go to `TELEMETRY_RINGBUF`. User-space applies static rules, behavioral frequency analysis, and (future) Wasm policies.

The 2026-07-12 draft of this table named a Rust tracepoint `neuromesh_exec_hook` and LSM `neuromesh_lsm_exec_guard` in one ELF, sharing one RingBuf. That prototype TP was **removed** in [PR #35](https://github.com/Neuromesh-Security/neuromesh/pull/35) (`dc06aeda`); it is not compiled, not verifier-tested, and not a future-work item. See Amendments.

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

## Amendments

### 2026-07-15 — Rust `neuromesh_exec_hook` removed ([PR #35](https://github.com/Neuromesh-Security/neuromesh/pull/35), `dc06aeda`)

The original Decision table named `neuromesh_exec_hook` as the passive
tracepoint inside the Rust eBPF object. That program was a prototype
`sys_enter_execve` hook. PR #35 deleted it to resolve split-brain C vs Rust
tracepoints. Production visibility is C `nm_proc_events` /
`nm_execveat` → `PROCESS_EVENTS`. Enforcement remains Rust `nm_lsm_bprm` →
`TELEMETRY_RINGBUF` (blocked events only). This **does not** reopen attaching
the Rust TP; it is historical, not a gap.

### 2026-08-16 — exec tracepoint coverage extended to `execveat` ([#126](https://github.com/Neuromesh-Security/neuromesh/issues/126))

This ADR's "Universal visibility: every `execve` is observed" claim held only for
`execve(2)`. `execveat(2)` — and therefore `fexecve(3)`, which glibc implements as
`execveat(fd, "", argv, envp, AT_EMPTY_PATH)` — entered the kernel through a
syscall the agent did not trace, so those executions were absent from the passive
stream even though the LSM hook still enforced against them.

The telemetry side now attaches `syscalls/sys_enter_execveat` (`nm_execveat`)
alongside `sys_enter_execve`, feeding the same `PROCESS_EVENTS` RingBuf through
the same rate limiter. This **does not change the dual-hook decision above** and
did not alter the enforcement plane: the asymmetry was always a visibility gap,
never a deny bypass, because both syscalls converge on `do_execveat_common()` →
`security_bprm_check()` → `bprm_check_security`.

Tracepoints were chosen over a kprobe on the shared `do_execveat_common()` entry
because that symbol is internal and commonly inlined, making the attach
unreliable across kernels, whereas syscall tracepoints are a stable ABI.

## Related work

- Context-aware telemetry enrichment (`SecurityTelemetryEvent` lineage fields)
- User-space Data Normalizer (spawn burst / fork-bomb detection)
- Wasm policy engine scaffolding (`wasm_policy.rs`)
