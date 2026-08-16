# Neuromesh Threat Model — eBPF Sensor Core

**Status:** Living document  
**Release scope:** `v0.1.0-core`  
**Last updated:** 2026-08-05  
**Component:** `apps/agent-ebpf-sensor` — kernel hooks, telemetry contracts, user-space detection pipeline

---

## 1. Scope and assumptions

### In scope

- C visibility programs: `sys_enter_execve` + `sys_enter_execveat` tracepoints, `tcp_connect` kprobe
- Rust enforcement program: `bprm_check_security` LSM hook
- User-space pipelines: `RuleEngine`, `DataNormalizer`, `CorrelationEngine`, Prometheus health
- Map pinning, rate limiting, and backpressure controls

### Out of scope (v0.1.0-core)

- Rust passive tracepoint `neuromesh_exec_hook` (built, not attached)
- Wasm policy evaluation on hot path (`wasm_policy.rs` scaffold only)
- Slow Path GNN inference (`ai-threat-detector`)
- Full argv/env capture from execve tracepoint context (capped argv landed in Issue #46; full env still out of scope)

### Assumptions

- Attackers have unprivileged or compromised user-level access on Linux nodes.
- Living-off-the-land (LotL) binaries (`bash`, `curl`, `python`, `sh`) are present and often whitelisted.
- LSM eBPF is the synchronous enforcement plane; user-space logic must remain correct when tested offline without a kernel.
- Operators monitor `ebpf_events_dropped_total` — unmonitored drops are treated as a production incident.

---

## 2. Assets and impact

| Asset | Description | Impact if compromised |
|-------|-------------|----------------------|
| `PROCESS_EVENTS` RingBuf | High-volume exec telemetry (`execve` + `execveat`/`fexecve`) | Missed process visibility, fork-bomb blind spots |
| `TELEMETRY_RINGBUF` | LSM enforcement telemetry | Missed blocks, silent allow of staging-path execution |
| `NETWORK_EVENTS` RingBuf | Outbound TCP connect telemetry | Missed C2 / lateral movement signals |
| `RuleEngine` policies | Whitelist / blacklist path rules | False negatives on staging paths; false positives on admin workflows |
| `DataNormalizer` | Parent-keyed spawn burst detector | Undetected fork bombs, post-exploitation automation |
| `CorrelationEngine` | PID → process name cache | Enriched network events lose process attribution |
| Orchestrator stdout / Kafka | Alert and telemetry export | Tampered or dropped SIEM records |

---

## 3. MITRE ATT&CK mapping — execve telemetry

### Covered techniques (v0.1.0-core)

| Technique | ID | Neuromesh control | Detection signal | Test anchor |
|-----------|-----|-------------------|------------------|-------------|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | LSM path classification + spawn burst analysis | `CRITICAL_ALERT` / `BEHAVIOR_ALERT` JSON | `rule_engine_integration`, `data_normalizer_integration` |
| Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Parent-keyed spawn frequency (`ppid` window) | `NEUROMESH-EXEC-SPAWN-BURST` | `rapid_spawn_burst_triggers_behavior_alert` |
| User Execution | [T1204](https://attack.mitre.org/techniques/T1204/) | LSM deny + blacklist on ephemeral paths | `NEUROMESH-EXEC-BLACKLIST-PATH` | `all_malicious_staging_prefixes_are_flagged` |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | `comm` + filename in LSM telemetry; PID correlation for network | Enriched network events | `pipeline_integration::mock_ringbuf_feeds_pipeline_without_kernel` |
| Endpoint Denial of Service | [T1499](https://attack.mitre.org/techniques/T1499/) | Kernel token bucket + spawn burst detection | Rate-limit drops; burst alerts | `execve_stress_test`, `data_normalizer_integration` |
| Non-Standard Port / Application Layer Protocol | [T1571](https://attack.mitre.org/techniques/T1571/) / [T1071](https://attack.mitre.org/techniques/T1071/) | `tcp_connect` kprobe visibility | Correlated network events → Kafka | Network monitor (manual validation) |

### Partially covered / planned

| Technique | ID | Gap | Planned mitigation |
|-----------|-----|-----|-------------------|
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | No `ptrace`/`memfd_create` hooks | v0.2 hook expansion |
| Impair Defenses | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Attacker with CAP_BPF can detach programs | Agent tamper detection, signed bytecode attestation |
| Hide Artifacts | [T1070](https://attack.mitre.org/techniques/T1070/) | Short-lived processes may evade correlation | Enriched C tracepoint (`neuromesh_exec_hook`) |
| Signed Binary Proxy Execution | [T1218](https://attack.mitre.org/techniques/T1218/) | LotL from whitelisted paths without burst | Wasm policies + Slow Path GNN |

---

## 4. `execve` telemetry — threat surface

The `sys_enter_execve` tracepoint is the highest-volume syscall surface in the agent. Attackers can abuse exec visibility for **evasion**, **denial of service**, and **telemetry poisoning** if controls are absent.

### 4.1 Threat scenarios

| ID | Threat | Description | MITRE alignment |
|----|--------|-------------|-----------------|
| E-01 | **Exec storm / fork bomb** | High-frequency `execve` floods RingBuf and user-space workers | [T1499](https://attack.mitre.org/techniques/T1499/) |
| E-02 | **Visibility evasion** | Sub-second processes exit before PID→name correlation registers | [T1036](https://attack.mitre.org/techniques/T1036/) |
| E-03 | **TOCTOU on argv/path** | User-space reads of `filename` after syscall entry; kernel/userspace views can diverge | [T1059](https://attack.mitre.org/techniques/T1059/) |
| E-04 | **Agent restart blind spot** | Unpinned maps reset rate-limiter state across crashes | Availability |
| E-05 | **Staging path execution** | Payload dropped to `/tmp/`, `/dev/shm/`, `/var/tmp/` and executed | [T1204](https://attack.mitre.org/techniques/T1204/) |
| E-06 | **LotL without burst** | Single invocation of whitelisted binary from benign path | [T1218](https://attack.mitre.org/techniques/T1218/) |
| E-07 | **BPF program tampering** | Root attacker unloads or replaces agent BPF programs | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |
| E-08 | **Rate-limit exhaustion** | Deliberate exec flood forces kernel drops, creating visibility gaps | [T1499](https://attack.mitre.org/techniques/T1499/) |

### 4.2 Kernel-level evasion risks

| Risk | Mechanism | Current exposure (v0.1.0-core) |
|------|-----------|----------------------------------|
| **Syscall alternative (`execveat` / `fexecve`)** | Attacker uses `execveat(2)` or `fexecve` instead of `execve(2)` hoping to skip deny-list enforcement | **Not an enforcement bypass.** Decision path is `neuromesh_lsm_exec_guard` on LSM hook `bprm_check_security` (aya `Lsm`, loaded/attached in `main.rs`). On supported kernels (~6.8 / ~6.17 Azure per CI), both `execve` and `execveat` enter `do_execveat_common()` → `bprm_execve()` → `exec_binprm()` → `search_binary_handler()` → `security_bprm_check()` → `call_int_hook(bprm_check_security, …)` (Linux `fs/exec.c` + `security/security.c`, tags `v6.8` / `v6.17`). Path-prefix deny therefore applies to both syscalls. (`clone3` is not an exec path; a later exec still hits the same LSM hook.) |
| **C process-visibility gap (`execveat`)** | Allowed `execveat` / `fexecve` never hits the C visibility attach | **Closed ([#126](https://github.com/Neuromesh-Security/neuromesh/issues/126)) — was observability only, never a security-control gap.** `sys_exec.bpf.c` now also carries `SEC("tracepoint/syscalls/sys_enter_execveat")` (`nm_execveat`), attached fail-closed in `process_monitor.rs` beside the `execve` attach. Allowed `execveat(2)` and `fexecve(3)` executions therefore reach `PROCESS_EVENTS` and the correlation stream, tagged with `EXEC_FLAG_SYSCALL_EXECVEAT`. **A single attach is sufficient, and a second is impossible:** `fexecve(3)` is not a syscall (there is no `__NR_fexecve`) but a libc function, and libc lowers it to one of exactly two syscalls — both of which are now traced. Modern glibc (≥ 2.27, where `__ASSUME_EXECVEAT` compiles the alternative out) and musl issue `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`, caught by the new `nm_execveat`; the legacy fallback, taken only when `execveat` returns `ENOSYS` (pre-3.19 kernels), issues `execve("/proc/self/fd/N", …)`, which the pre-existing `nm_proc_events` attach already caught. `fexecve` is thus visible under either lowering, differing only in label and in whether the path resolves. **Enforcement was unchanged by this work** — deny always ran on the shared LSM path above. Residual, specific to the `AT_EMPTY_PATH` lowering: that syscall carries no path string, so `filename` is the `UNKNOWN` sentinel with `CAPTURE_FILENAME` raised and `EXEC_FLAG_PATH_FROM_FD` set — pid/ppid/uid, container, and `argv` are still captured, but the binary is not attributed by path. Resolving the dirfd would require an fd-table walk and is deliberately out of scope. (The `/proc/self/fd/N` lowering does yield a usable path.) |
| **Namespace escape context** | Container breakout before agent deploy | Agent must run on host PID namespace (`hostPID: true`) |
| **BPF hook disable** | `CAP_BPF` + `CAP_SYS_ADMIN` attacker detaches programs | **Partial tamper-evidence (PR [#74](https://github.com/Neuromesh-Security/neuromesh/pull/74)/[#76](https://github.com/Neuromesh-Security/neuromesh/pull/76)), not a new gap.** Periodic integrity monitor detects LSM/deny-map **pin removal** and **agent binary replacement** within ≤60s (default 45s). Same residual as §7 **Agent tampering by root** / E-07: determined root who also controls the alert channel or re-signs with a stolen key is out of scope for open-source core. Does not re-hash loaded BPF bytecode or deny-map **contents**. |
| **Verifier-minimal telemetry** | C tracepoint emits PID-only records | **Mitigated for argv ([#46](https://github.com/Neuromesh-Security/neuromesh/issues/46)):** `sys_enter_execve` already captures pid/comm/filename/lineage; capped argv (256-byte NUL-separated) added in `ExecEvent` v2. Env capture still out of scope. |
| **BTF offset coverage gap** | Rust LSM reads `linux_binprm` / `task_struct` fields via BTF-resolved offsets injected at load time (hardcoded offsets removed in PR #49) | Offsets are fail-closed at agent startup when BTF resolution fails; residual risk is **unvalidated kernels** (see §7) — wrong or untested ABIs are not silently papered over with guessed constants, but CI has not proven every claimed LTS line |
| **Kprobe offset drift** | `tcp_connect` socket field offsets from minimal `vmlinux.h` | Dest IP/port read failure on kernel ABI change |
| **RingBuf loss under load** | Legitimate high exec rate exceeds 500k/sec/CPU | Events dropped by design — attacker can hide in noise |
| **LSM bypass paths** | Execution paths not passing `bprm_check_security` | Kernel-dependent; no agent coverage claim for all exec variants |

### 4.3 Mitigation strategies

| Control | Implementation | Threats addressed |
|---------|----------------|-----------------|
| **Kernel token bucket** | `RATE_LIMIT_BUCKET` per-CPU (~500k evt/s) in `sys_exec.bpf.c` | E-01, E-08 |
| **RingBuf backpressure** | Bounded Tokio MPSC (`NEUROMESH_PROCESS_CHANNEL_CAPACITY`, default 8192) | E-01 |
| **BPFfs map pinning** | `PROCESS_EVENTS` + `RATE_LIMIT_BUCKET` under `/sys/fs/bpf/neuromesh` | E-04 |
| **LSM synchronous deny** | `neuromesh_lsm_exec_guard` returns `-EPERM` when the exec path matches the centrally-governed BPF path-prefix deny map (Phase 1; bootstrap defaults remain `/tmp/`, `/dev/shm/`, `/var/tmp/`) | E-05 |
| **BTF-resolved field access** | Orchestrator resolves `BPRM_FILENAME_OFFSET` / `TASK_*` from live `/sys/kernel/btf/vmlinux` and injects globals before load (PR #49); no hardcoded `task_struct` offset fallback | E-06 (ppid lineage); removes the prior hardcoded-offset hazard |
| **Spawn burst detection** | `DataNormalizer` — 2s window, threshold 8 spawns per `ppid` | E-01, E-06 (partial) |
| **Path whitelist suppression** | Static whitelist: `/bin/ls`, `/bin/cat`, `/usr/bin/git`, `/usr/bin/bash` | False positive reduction |
| **Graceful shutdown** | `CancellationToken` + 500ms drain before BPF link release | Data loss on rolling update |
| **Prometheus + health monitor** | `ebpf_events_dropped_total`, 5s kernel drop sampling | E-08 detection |
| **Fuzz-tested decoders** | `event_parser_fuzz_test` — 50k random-byte iterations | Memory safety in user-space decode |
| **Chaos-tested backpressure** | `chaos_engineering_test` — MPSC saturation, 50k mock RingBuf drain | E-01 resilience validation |

### 4.4 False-positive handling

False positives erode SOC trust. Neuromesh applies layered suppression:

#### RuleEngine (path-based)

| Policy | Paths / prefixes | Behavior |
|--------|------------------|----------|
| **Whitelist (exact match)** | `/bin/ls`, `/bin/cat`, `/usr/bin/git`, `/usr/bin/bash` | `RuleVerdict::Suppressed` — no alert emitted |
| **Blacklist (prefix match)** | `/tmp/`, `/dev/shm/`, `/var/tmp/` | `CRITICAL_ALERT` / `NEUROMESH-EXEC-BLACKLIST-PATH` |
| **Default** | All other paths | Suppressed (no alert on benign paths) |

**Operational guidance:**

- Extend whitelist via code change (v0.1.0-core) — no runtime policy API yet.
- Treat `/tmp/` alerts as **high-confidence staging detections**, not automatic block in user space (block already occurred in LSM for matched paths).
- Document approved temporary execution paths for CI/CD (e.g., package managers writing to `/var/tmp/`) — add to whitelist or relocate artifacts.

#### DataNormalizer (behavior-based)

| Parameter | Default | False-positive scenario | Tuning |
|-----------|---------|------------------------|--------|
| Window | 2 seconds | Build systems spawning many short-lived children | Increase window or threshold |
| Burst threshold | 8 spawns per `ppid` | Parallel test runners | Raise threshold via `with_config()` |
| `ppid == 0` (no capture fault) | Ignored | Orphan / init-edge lineage; correlating all such events into a shared `0` bucket would FP | Do not alert on genuine orphan events |
| `ppid` capture fault (`CAPTURE_PPID` → `ppid_unresolved`) | Counted under **comm** fallback | Per-event probe miss after successful BTF load (rare on supported kernels; structural BTF failure is fail-closed at startup — see §4.2/§4.3) | Alert tagged `ppid_unresolved=true`; `ppid` remains `0` and must not be treated as parent 0 |

**Operational guidance:**

- `BEHAVIOR_ALERT` severity is **`BEHAVIOR_ALERT`** (not `CRITICAL`) — route to triage queue, not auto-remediation.
- Correlate with parent `comm` and `last_binary_path` before escalation.
- CI burst jobs should run with tagged parent processes or excluded nodes.

#### Telemetry volume FPs

| Signal | Cause | Response |
|--------|-------|----------|
| High `ebpf_events_processed_total` without alerts | Normal workload | Baseline per node class |
| `ebpf_events_dropped_total` > 0 | Exec rate exceeds capacity | Scale agent CPU; investigate fork bomb (E-01) |
| Log sampling every 10k events | Info-level process monitor logs | Do not treat sampled logs as security alerts |

### 4.5 Phase 1 — centrally-governed path-prefix deny list (control-plane sync)

Phase 1 (PR #50) replaces the LSM's compile-time hardcoded path-prefix compare with
an in-kernel lookup against BPF arrays (`PATH_DENY_LIST` / `PATH_DENY_COUNT`) that
userspace populates from zt-policy-engine. This matches the dual-hook split in
[ADR-001](architecture-decision-records/adr-001-lsm-vs-tracepoint.md): **the LSM still
decides synchronously in-kernel**; the control plane only governs *what* prefix set
is enforced, out-of-band.

**Prefix key width:** `PATH_DENY_KEY_BYTES` is **32** (Issue [#134](https://github.com/Neuromesh-Security/neuromesh/issues/134)) —
proactive headroom above the historical 16-byte window. Bootstrap prefixes remain
`/tmp/` (5), `/dev/shm/` (9), `/var/tmp/` (9). Over-length prefixes are
**fail-closed rejected** at `PathDenyEntry::from_prefix` / bundle parse (never
silently truncated). Map value ABI changes with this constant — upgrade requires
reloading the enforcement object (unpin + reattach), not hot-patching an old map.

#### Three planes (what is connected vs not)

| Plane | Role in Phase 1 | Hot-path network? |
|-------|-----------------|-------------------|
| **In-kernel LSM** (`neuromesh_lsm_exec_guard`) | Per-`execve` allow/deny via bounded BPF Array scan + `starts_with` | **Never** — map lookup only |
| **Control-plane sync** (`GET /v1/policy-bundle` → agent) | Periodically refreshes the deny-list maps | Userspace HTTP only (not in the LSM) |
| **Slow Path** (`POST /v1/evaluate`) | OPA + SPIFFE audit/eval endpoint | **Disconnected** from enforcement — not called by the agent or LSM |

#### Bundle API and agent sync (current behavior)

`GET /v1/policy-bundle` (`apps/zt-policy-engine/internal/policybundle`) returns JSON
under **two independent controls** (neither replaces the other):

1. **Transport auth (Issue [#55](https://github.com/Neuromesh-Security/neuromesh/issues/55))** —
   `Authorization: Bearer <token>` via `NEUROMESH_POLICY_BUNDLE_TOKEN` or
   Secret-mounted `NEUROMESH_POLICY_BUNDLE_TOKEN_FILE`. Unauthenticated / invalid →
   **401**. PE fatal at startup if the token is unset (fail-closed).
2. **Content integrity (Issue [#108](https://github.com/Neuromesh-Security/neuromesh/issues/108)
   / external Rego–policy-bundle review P0, T-PB-02-class)** — Cosign
   `sign-blob` / `verify-blob` detached signature over the **exact HTTP response
   body bytes** (full JSON: `deny_path_prefixes` **and**
   `identity_allow_exceptions`, including timestamps). Wire header:
   `X-Neuromesh-Policy-Bundle-Signature: <standard base64>`. PE signs at serve-time
   with PKCS#8 PEM from **`NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH`** (ECDSA P-256
   or Ed25519). **PE refuses to boot** if that path is missing, relative,
   unreadable, or not a supported key — there is **no** unsigned serve mode.
   Agent verifies with `NEUROMESH_POLICY_BUNDLE_PUBLIC_KEY_PATH` (fallback
   `NEUROMESH_COSIGN_PUBLIC_KEY_PATH`, default `/etc/neuromesh/cosign/cosign.pub`)
   **before** `apply_deny_entries` / `apply_identity_validity`. Missing or invalid
   signature → sync failure (`signature_missing` / `signature_invalid`); last-known-good
   deny retained.

SPIFFE mTLS was evaluated and deferred: this repo does not ship SPIRE on nodes today.
Bearer alone is **not** content integrity — a channel controller (PE impersonator,
MITM holding a stolen token) must not be able to weaken deny prefixes or widen
identity exceptions without a matching signature.

| Field | Meaning |
|-------|---------|
| `schema_version` | Document schema (`3` as of T-PB-04; agent parses `1`\|`2`\|`3` for deny prefixes; **signed sync requires `3`**) |
| `version` | Content-addressed `sha256:…` of deny prefixes + identity scope + SPIFFE IDs (timestamps **and** `not_before`/`not_after` excluded from hash churn; **still covered by the body signature**) |
| `not_before` / `not_after` | Whole-bundle RFC3339 temporal binding (T-PB-04). Inside signed body. Default window **300s** (10 × 30s sync; aligns with `POLICY_STALE_AFTER`). Agent accepts with **±5s** clock skew. Independent of identity `expires_at`. |
| `deny_path_prefixes` | Deny prefixes — Phase 1 set: `/tmp/`, `/dev/shm/`, `/var/tmp/` |
| `identity_allow_exceptions` | Slice 2a: `{ scope_path_prefix, spiffe_ids, issued_at, expires_at }` (identity VALID TTL only — **not** anti-replay) |
| *(header)* `X-Neuromesh-Policy-Bundle-Signature` | Detached Cosign-compatible signature over exact body bytes — **not** a JSON field inside the signed document |

#### Slice 2a identity exceptions (schema_version 2)

| Behavior | Detail |
|----------|--------|
| **Scope** | Exceptions apply **only** when path starts with `/tmp/` (agent rejects any other `scope_path_prefix`) |
| **SPIFFE IDs** | Path-form only (`spiffe://{trust}/ns/{ns}/sa/{sa}`) — matches Rego + real SPIRE SVIDs |
| **TTL** | `expires_at = issued_at + 90s` (3× sync interval). When exceeded → `IDENTITY_EXCEPTIONS_VALID=0` for **ALL** exceptions including manual seeds — **intentional, no grace period** |
| **Kernel maps** | `IDENTITY_ALLOW_CGROUPS` (HashMap u64→u8, max **16384** as of Slice 2b-ii-A), `IDENTITY_EXCEPTIONS_VALID` (Array@1) — **not pinned** (die with agent) |
| **LSM order** | deny-list hit → `/tmp/` only → VALID fresh → cgroup allow → else DENY |
| **Manual seed** | `NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS` remains **lab/test only**; loud `SECURITY WARNING`; **absent from all `deploy/kubernetes/` manifests**. Production path is Slice **2b-ii** auto-correlation (cgroup↔pod↔SPIFFE ∩ PE allowlist) — manual seed is **not** required for the verified insert path |
| **Production readiness (engineering)** | Slice **2a + 2b-i + 2b-ii (A/B/C)** are merged and **live-verified end-to-end** on a single-node k3s droplet (see below). That is **engineering verification**, not a multi-node soak, multi-tenant production cluster under load, or external audit. Manual seeding is no longer required for the auto-correlation path that was proven live. |

#### Slice 2b correlator — live verification status (2b-ii-C)

| Slice | What shipped | Status |
|-------|--------------|--------|
| **2a** | PE `identity_allow_exceptions`, LSM `/tmp/` gate, VALID TTL, lab manual seed | Merged |
| **2b-i** | Pod DELETE informer + cgroup teardown invalidation + side table | Merged; teardown residual measured earlier (see §7) |
| **2b-ii-A** | Auto-insert (SPIFFE path-form ∩ PE allowlist), PE revoke-on-sync, map capacity 16384 | Merged ([Issue #95](https://github.com/Neuromesh-Security/neuromesh/issues/95) / PR #96) |
| **2b-ii-B** | Multi-container burst teardown | Merged (PR #97) |
| **2b-ii-C** | Host-agent ↔ k3s live gate | Merged (PR #98); script [`scripts/manual_verify_identity_2bii_correlation.sh`](../scripts/manual_verify_identity_2bii_correlation.sh) |

**2b-ii-C live run (single droplet sample — not a distribution):** host agent on the same node as k3s (`neuromesh-dev-lab`), real multi-container pod (main + 2 sidecars), SPIFFE `spiffe://neuromesh.security/ns/default/sa/default`, **no** `NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS`. Confirmed via **agent log evidence** and Prometheus `identity_correlator_invalidation_total{reason=…}` — not script PASS lines alone:

| Scenario | Path / evidence | Measured latency (one sample) |
|----------|-----------------|-------------------------------|
| Auto-insert (3 container cgroup_ids) | `auto-inserted IDENTITY_ALLOW_CGROUPS entry (2b-ii-A)` ×3 | **~2.3 s** (Ready → all map keys present; includes apiserver watch + cgroup resolve) |
| Delete invalidation | `reason=pod_delete` (and/or teardown race) | **~0.9 s** (`terminationGracePeriodSeconds: 0`) |
| PE revoke while pod **Running** | `reason=pe_allowlist_revoke` | **~11.8 s** (gated by `POLICY_SYNC_INTERVAL` ≈ 30 s — **by design**, not watch lag) |

These are **single-sample** numbers from one droplet run. Do **not** treat them as p50/p99 or an SLA. Recommend repeating 5–10× (and broader environments) before any procurement/SLA claim. This verification is **single-node k3s**, not multi-node / multi-tenant production under real load, and does **not** replace a full production soak or external audit.

Agent behavior (`apps/agent-ebpf-sensor/src/policy_sync.rs`, `path_deny.rs`, `identity_allow.rs`):

| Behavior | Detail |
|----------|--------|
| **Poll cadence** | Every **30 seconds** (`POLICY_SYNC_INTERVAL`) when `NEUROMESH_ZT_POLICY_ENGINE_URL` is set |
| **HTTP timeout** | 5 seconds per request |
| **Authentication** | Bearer token required on every sync; **no** unauthenticated fallback |
| **Signature verification** | Cosign verify-blob over exact body **before** any map apply; missing/invalid → sync failure (`signature_missing` / `signature_invalid`); **no** unsigned apply |
| **Temporal binding (T-PB-04)** | After signature + parse, before any `apply_*`: require schema 3 + `not_before`/`not_after`; reject `bundle_expired` / `bundle_not_yet_valid` / `bundle_temporal_missing` (±5s skew); same LKG as signature failures |
| **Bootstrap (fail-closed)** | Before LSM attach, maps are seeded with `/tmp/`, `/dev/shm/`, `/var/tmp/` — never start with an empty deny map |
| **Sync failure (auth, signature, temporal, malformed JSON)** | Last-known-good map contents are **retained** (not cleared); enforcement continues |
| **STALE** | After **5 minutes** without a successful sync (`POLICY_STALE_AFTER`), state is logged as STALE — **enforcement is not disabled** |
| **Sync disabled** | If `NEUROMESH_ZT_POLICY_ENGINE_URL` is unset, sync is off; the agent enforces the bootstrap set only. If URL is set but the token **or** verify pubkey is missing, sync stays off and **does not** send unauthenticated / unverified requests |

#### Phase 2 identity exceptions — locked scope decisions (Slice 0)

These are **policy decisions**, not implementation details, recorded before Slice 2a/2b:

1. **`/tmp/`-only exception scope:** When identity exceptions are eventually wired into
   the LSM, they apply **only** to `/tmp/` (matching `execution.rego` today).
   `/dev/shm/` and `/var/tmp/` remain **hard-denied for every workload**, identity
   irrelevant. Widening that set requires an explicit Rego + threat-model change —
   not an accidental side effect of Phase 2 plumbing.
2. **`cgroup_id` recycling (Slice 2b — complete for engineering verification):** Kernel
   cgroup IDs can be reused after a pod/container is deleted and a new one is scheduled.
   Identity maps keyed by `cgroup_id` **must** invalidate entries on pod deletion **and**
   cgroup teardown, **not** rely on TTL expiry alone. **Slice 2b-i** implements: (1)
   node-local Pod informer (`fieldSelector=spec.nodeName=…`) → side-table lookup → BPF
   map delete; (2) inotify cgroup-directory teardown watch (parent `DELETE`/`MOVED_FROM`
   on cgroupfs + systemd path layouts) as the primary recycle-race closer. **Measured
   residual (lab cgroup teardown → BPF map delete):** **23.235 ms** on droplet hardware —
   **one** real sample via [`scripts/manual_verify_identity_invalidation.sh`](../scripts/manual_verify_identity_invalidation.sh),
   **not** a statistical distribution (see §7). **Slice 2b-ii** adds auto-insert
   (SPIFFE ∩ PE) and PE revoke-on-sync; **2b-ii-C** live-verified Pod DELETE
   (`reason=pod_delete`) and PE revoke (`reason=pe_allowlist_revoke`) on real k3s with
   agent log + metrics evidence (see Slice 2b table above). Follow-up: repeat latency
   samples 5–10× for range/p99 before any SLA claim. A stale allow entry surviving until
   TTL could otherwise let a newly scheduled untrusted pod transiently inherit a deleted
   trusted pod’s recycled `cgroup_id` and its allow status. **Honest residual:**
   sub-second-to-tens-of-ms windows remain possible under agent CPU starvation or inotify
   overflow (overflow → fail-closed forced resync). **Not** claimed zero-window; **not**
   claimed multi-node production soak.
---

## 5. Network telemetry (`tcp_connect`)

| Threat | Control | Residual risk |
|--------|---------|---------------|
| C2 over non-TCP protocols | Not visible to kprobe | UDP/ICMP blind spot |
| Connect before agent start | No retroactive visibility | Deploy agent before workload |
| Correlation miss (unknown PID) | Event logged, not Kafka-enqueued | Short-lived process (E-02) |

---

## 6. Test farm coverage

Integration tests run via `cargo test -p neuromesh-integration-tests` **without** a Linux kernel:

```
/tests
  src/fixtures.rs          # Benign / malicious telemetry vectors
  src/mocks.rs             # MockRingBuf + TelemetrySource trait
  tests/
    rule_engine_integration.rs
    data_normalizer_integration.rs
    pipeline_integration.rs
```

### Fixture → ATT&CK traceability

| Fixture vector | MITRE intent | Expected outcome |
|----------------|--------------|------------------|
| `benign_events()` | Baseline admin activity | `RuleVerdict::Suppressed`, no `BEHAVIOR_ALERT` |
| `malicious_blacklist_events()` | T1204 — staging in ephemeral dirs | `CRITICAL_ALERT` / `NEUROMESH-EXEC-BLACKLIST-PATH` |
| `malicious_spawn_burst_events()` | T1059 / T1499 — rapid interpreter chaining | `BEHAVIOR_ALERT` / `NEUROMESH-EXEC-SPAWN-BURST` |
| `mixed_ringbuf_drain()` | Combined kill-chain simulation | Both SIEM and behavioral alerts |

### Offline eBPF mocking

| Kernel construct | Test double | Location |
|------------------|-------------|----------|
| `TELEMETRY_RINGBUF` | `MockRingBuf::from_events(vec![])` | `agent_ebpf_sensor::mocks::ringbuf` |
| Map health counters | `TelemetryHealthStats` on mock drain | `pipeline_integration` |
| Async poll loop | `TelemetrySource` trait | `agent_ebpf_sensor::mocks::telemetry_source` |

---

## 7. Residual risks (v0.1.0-core)

> **Ownership note (2026-07-17):** `Owner`/`Target` columns added below following
> two independent audit findings that High/Medium residual risks were disclosed
> but unowned — an acknowledged-but-unowned finding reads worse in a Fortune 500
> security review than an undisclosed one. `Agent tampering by root` is tracked
> in [#44](https://github.com/Neuromesh-Security/neuromesh/issues/44); the
> remaining Medium-severity rows below are flagged as needing their own issues
> (`Tracked in #TBD`) and are intentionally NOT assigned a real issue number or
> a named owner here until those issues exist — do not treat `#TBD` as a real
> reference.

| Risk | Severity | Notes | Owner | Target |
|------|----------|-------|-------|--------|
| C execve tracepoint argv capture | Medium → **Mitigated ([#46](https://github.com/Neuromesh-Security/neuromesh/issues/46))** | Capped argv capture landed in `ExecEvent` schema v2: **8 slots × 32 bytes** via `bpf_probe_read_user` + `bpf_probe_read_user_str` on `sys_enter_execve` argv (not `bprm`). **Truncation is explicit:** per-slot `argv_trunc_mask` (bit i when slot i filled the 32 B buffer), `argv_flags` (`ARGC_TRUNCATED` / `PROBE_FAULT`), `CAPTURE_ARGV`, and CRITICAL_ALERT JSON fields `argv_truncated` + `argv_trunc_mask` — analysts must not treat a filled slot as a proven-complete argument. Residual: full env; content beyond caps. Ringbuf depth drops ~39% vs v1 (668 B vs 408 B in a 1 MiB `PROCESS_EVENTS`) — real secondary drop risk under consumer lag; primary backpressure remains the 500k EPS token bucket. | Dragan Flavius (@DraganFlavius) | Closed via [#46](https://github.com/Neuromesh-Security/neuromesh/issues/46) / PR #77 |
| `neuromesh_exec_hook` not attached | Low | Rich passive telemetry exists but unused at runtime | — | — |
| Per-CPU drop accounting | Low | `RATE_LIMIT_DROPS` summed across CPUs; NUMA hot spots may dominate | — | — |
| BTF offset resolver — cross-kernel coverage (hardcoded offsets RESOLVED) | Medium | **Resolved (PR #49):** the Rust LSM no longer uses compile-time hardcoded `task_struct` / `linux_binprm` offsets; the orchestrator resolves them from live BTF and aborts startup on resolution failure (no guessed-offset fallback). **Labeling fixed ([#52](https://github.com/Neuromesh-Security/neuromesh/issues/52)):** CI matrix jobs are now honestly named `ubuntu-22.04 / ~6.8-azure` and `ubuntu-24.04 / ~6.17-azure` (duplicate aspirational `"5.15"`/`"6.1"` cells collapsed — real coverage unchanged at two Azure HWE kernels). **Still open (severity not reduced):** live validation still does **not** cover real 5.15 / 6.1 LTS (or true non-Azure 6.8). Unit tests + one WSL2 5.15.167 fixture are cross-checked against bpftool ground truth but do not substitute for those pre-release hardware checks before those lines are claimed as validated. | Unassigned | Tracked in #TBD — new issue needed (real LTS hardware validation); labeling accuracy closed via #52 |
| `execveat` as enforcement bypass (clarified) | Medium → **Not a bypass** | **Clarified ([#46](https://github.com/Neuromesh-Security/neuromesh/issues/46)):** do **not** treat “no `execveat` hook” as an exploitable deny-list bypass. Enforcement/decision is covered by the shared LSM hook `bprm_check_security` (`neuromesh_lsm_exec_guard`). Kernel architecture on the CI matrix (~6.8 / ~6.17): `execve` and `execveat` both funnel through `do_execveat_common` → … → `security_bprm_check` → `bprm_check_security`. No second LSM attach is required for `execveat` enforcement. | — | Closed as enforcement concern via #46 investigation; docs updated |
| C telemetry: no `sys_enter_execveat` | Low → **Closed ([#126](https://github.com/Neuromesh-Security/neuromesh/issues/126))** | **Observability gap closed; enforcement was never affected.** `sys_exec.bpf.c` adds `nm_execveat` on `SEC("tracepoint/syscalls/sys_enter_execveat")`, attached fail-closed in `process_monitor.rs` alongside the `execve` attach, so allowed `execveat`/`fexecve` now reach process-visibility/correlation. Both tracepoints share `emit_exec_event()` (identical capture semantics) and the same `RLIMIT_BUCKET` token bucket, so the aggregate admitted rate stays at the one ~500k EPS ceiling `PROCESS_EVENTS` was already sized against — no RingBuf resize was required. Variant is reported via `EXEC_FLAG_SYSCALL_EXECVEAT` in the previously-unused `ExecEvent::flags` header byte, so `struct_size` stays 668 and `is_valid()` is unchanged. No `fexecve`-specific attach exists or is needed: `fexecve(3)` has no syscall of its own and lowers either to `execveat`+`AT_EMPTY_PATH` (modern glibc/musl → `nm_execveat`) or, on pre-3.19 kernels, to `execve("/proc/self/fd/N", …)` (→ the pre-existing `nm_proc_events`). **Remaining sub-residual (Low):** under the `AT_EMPTY_PATH` lowering the syscall carries no path string, so the record is reported as `UNKNOWN` + `CAPTURE_FILENAME` + `EXEC_FLAG_PATH_FROM_FD` rather than path-resolved; pid/ppid/uid, container, and `argv` are still captured. dirfd→path resolution needs an fd-table walk and is out of scope. | Dragan Flavius (@DraganFlavius) | Closed via [#126](https://github.com/Neuromesh-Security/neuromesh/issues/126); superseded the [#46](https://github.com/Neuromesh-Security/neuromesh/issues/46) telemetry follow-up |
| LotL single-shot from whitelisted path | Medium | Requires Slow Path / Wasm (future). Planned mitigation: Wasm policy engine + Slow Path GNN correlation (currently scaffold-only, see §3). | Unassigned | Tracked in #TBD — new issue needed |
| Agent exit tore down LSM deny (unpinned link) | High → **Mitigated (PR #72)** | **Resolved for survival:** LSM link pinned at `{NEUROMESH_BPF_PIN_ROOT}/neuromesh_lsm_exec_guard_link` and deny maps at `PATH_DENY_LIST` / `PATH_DENY_COUNT` (bpffs forbids `.` in pin basenames); pin failure aborts startup (fail-closed). Empirically verified: deny survives `kill -9` of the agent on a live BPF-LSM kernel. | Dragan Flavius (@DraganFlavius) | Closed via [#44](https://github.com/Neuromesh-Security/neuromesh/issues/44) / PR #72 |
| Agent tampering by root | High → **Mitigated (Phase 1 + Phase 2 + on-disk path)** | **Phase 1 (PR #62):** Cosign-static-key signed bytecode manifest verified fail-closed at startup *before* any BPF load — three embedded objects (`sys_exec.bpf.o`, `network_filter.bpf.o`, LSM enforcement ELF). **Agent binary:** not in that manifest (circular by design). **Expected digest for Phase 2 / #75 (default):** the agent **self-hashes `/proc/self/exe` once when the integrity monitor arms** and remembers that value for the process lifetime — this is **not** an independent operator-published Cosign-adjacent source of truth. Optional override `NEUROMESH_AGENT_EXE_DIGEST=sha256:<hex>` exists in code but has **no** README/runbook / published digest artifact today, so production behavior is the self-baseline. **Limitation:** a self-established baseline does **not** detect day-zero compromise (binary already tampered *before* first start); it only detects **later** drift of the running inode and/or on-disk install path vs that first-start snapshot. Day-zero agent-binary provenance remains image Cosign (admission) + Phase 1 bytecode objects, not this env. **PR #72:** pinned LSM link + deny maps so exit/crash does not drop enforcement. **Phase 2 (PR #74):** periodic monitor re-hashes `/proc/self/exe` (running inode), confirms pinned LSM link via `PinnedLink::from_pin` + `FdLink::info()`, and confirms deny-map pins. **On-disk residual closed ([#75](https://github.com/Neuromesh-Security/neuromesh/issues/75)):** second independent check opens the install path **by name** (`readlink(/proc/self/exe)` at arm time, strip ` (deleted)`, or `NEUROMESH_AGENT_ON_DISK_PATH`) and compares to the same expected digest — detects `unlink`+replace that `/proc/self/exe` alone misses. Failures increment `agent_integrity_failure_total{reason=exe_digest\|on_disk_binary\|lsm_link\|pinned_map}`; default **alert + exit** (`NEUROMESH_INTEGRITY_EXIT_ON_FAILURE=true`). Evidence-only (TOCTOU between hash and exit possible). Production install path is `/usr/local/bin/agent-ebpf-sensor` (Dockerfile + DaemonSet `command`) but is resolved at runtime, not hardcoded. Does **not** stop a determined root who also controls the alert channel or re-signs with a stolen key. Live droplet scenarios in `scripts/manual_verify_runtime_integrity.sh` (pinned_map + unlink+replace) gate merge approval. | Dragan Flavius (@DraganFlavius) | Closed via [#44](https://github.com/Neuromesh-Security/neuromesh/issues/44) + [#75](https://github.com/Neuromesh-Security/neuromesh/issues/75) |
| Unauthenticated `GET /v1/policy-bundle` | Low → **Mitigated (Slice 0)** | **Resolved for auth:** endpoint requires shared Bearer token (`NEUROMESH_POLICY_BUNDLE_TOKEN` / `_FILE`); agent never falls back to unauthenticated sync; auth failure retains last-known-good deny maps. Residual: static shared secret must be provisioned/rotated (same class as Cosign static keys) until SPIRE-based mTLS is operable in deploy. Identity allowlist content ships in Slice 2a (schema_version 2) over this authenticated path. **Does not** by itself prove bundle bytes were untampered — see next row. | Dragan Flavius (@DraganFlavius) | Tracked in [#55](https://github.com/Neuromesh-Security/neuromesh/issues/55) |
| Policy-bundle content integrity (T-PB-02-class) | High → **Mitigated (Issue [#108](https://github.com/Neuromesh-Security/neuromesh/issues/108))** | **Pre-signing residual (after Issue #55 alone):** bearer auth proved *who may fetch*, not *what was authorized to apply*. A channel controller (PE impersonator, MITM holding a stolen token) could serve a weakened `deny_path_prefixes` set or widened `identity_allow_exceptions` and the agent would apply it — LSM policy bypass. Severity **High** (enforcement integrity), not a downgrade of the auth-only row (that row stays Low→Mitigated for *unauthenticated* access). **Mitigation:** Cosign-compatible detached signature over exact body bytes; PE fail-closed without `NEUROMESH_POLICY_BUNDLE_SIGNING_KEY_PATH`; agent verifies before any `apply_*`; missing/invalid → last-known-good. Live gate: [`scripts/manual_verify_policy_bundle_signature.sh`](../scripts/manual_verify_policy_bundle_signature.sh). **Residual (Medium, not High→Low):** static signing-key / pubkey compromise or agent pubkey swap — same class as Cosign bytecode keys; prefer dedicated policy-bundle keypair in production for blast-radius isolation. Does **not** reduce “Agent tampering by root” (still High→Mitigated on its own path). | Dragan Flavius (@DraganFlavius) | [#108](https://github.com/Neuromesh-Security/neuromesh/issues/108) / PR #109 |
| Policy-bundle anti-replay temporal binding (T-PB-04) | High → **Mitigated** | **Pre-mitigation:** a correctly signed body could be captured and replayed later (stale deny set / widened exceptions) because signature alone does not prove freshness. **Mitigation:** top-level `not_before` / `not_after` (RFC3339) **inside** the Cosign-signed JSON (schema_version **3**); PE sets `not_before=now`, `not_after=now+300s` (10 × 30s sync; override `NEUROMESH_POLICY_BUNDLE_VALIDITY_SECS` for short-window live tests); agent accepts with **±5s** skew (`NEUROMESH_POLICY_BUNDLE_CLOCK_SKEW_SECS`); rejects `bundle_expired` / `bundle_not_yet_valid` / `bundle_temporal_missing` before any `apply_*` (same LKG as signature failures). Do **not** repurpose `identity_allow_exceptions.expires_at` (identity VALID TTL only). Live gate extended in [`scripts/manual_verify_policy_bundle_signature.sh`](../scripts/manual_verify_policy_bundle_signature.sh) (capture → wait → replay exact bytes). **Residual:** host clock compromise; very short replay still possible within the validity window. | Dragan Flavius (@DraganFlavius) | Grok audit #3 / follows [#108](https://github.com/Neuromesh-Security/neuromesh/issues/108) |
| Phase 2 identity exceptions / correlator | Medium → **Mitigated (engineering verification; Slice 2a+2b)** | Slice 2a (PE exceptions + LSM `/tmp/` gate) + **2b-i** (DELETE + teardown invalidation) + **2b-ii A/B/C** (auto-insert SPIFFE ∩ PE, multi-container teardown, live k3s gate) are **merged**. Live-proven on single-node k3s without manual seed: insert, `pod_delete`, `pe_allowlist_revoke` (agent log + `identity_correlator_invalidation_total`). Manual seed env must never appear in `deploy/kubernetes/`. **Not** a production soak / external audit. | Dragan Flavius (@DraganFlavius) | Closed via [#92](https://github.com/Neuromesh-Security/neuromesh/issues/92) + [#95](https://github.com/Neuromesh-Security/neuromesh/issues/95) / PRs #96–#98 |
| Phase 2 `cgroup_id` recycling | Medium → **Mitigated (2b-i + 2b-ii; residual window)** | Invalidate on Pod DELETE **and** cgroup teardown; auto-insert + PE revoke-on-sync live-verified (2b-ii-C). Lab teardown residual sample **23.235 ms** (one sample). Live delete ~0.9 s / revoke ~11.8 s on one droplet run (revoke PE-sync-gated). Overflow → fail-closed resync. **Not** zero-window; repeat samples before SLA claims. | Dragan Flavius (@DraganFlavius) | Issue [#92](https://github.com/Neuromesh-Security/neuromesh/issues/92) / [#95](https://github.com/Neuromesh-Security/neuromesh/issues/95) |
| Slice 2b-i Pod DELETE informer live verification | Medium → **Mitigated (2b-ii-C)** | Previously unit-test-only. **Closed** by Slice 2b-ii-C live run on k3s: Pod DELETE invalidation observed with `reason=pod_delete` (agent log + metrics) on a real multi-container pod. Same engineering-scope limits as the 2b-ii-C table (single node, single sample). | Dragan Flavius (@DraganFlavius) | Closed via [#95](https://github.com/Neuromesh-Security/neuromesh/issues/95) / PR #98 |
| Slice 2b correlator RBAC pod visibility | Low–Medium | DaemonSet SA gains ClusterRole `get/list/watch` on `pods` (no secrets/exec/proxy/writes). Kubernetes RBAC cannot scope to “this node only”; `spec.nodeName` fieldSelector is data-plane filtering only. Same class as other node agents. | Unassigned | Issue [#92](https://github.com/Neuromesh-Security/neuromesh/issues/92) |
| CI coverage gate | Low | ≥70% line coverage on core crates; Ring 0 not measured | — | — |

---

## 8. Validation workflow

### Offline (no root, no kernel)

```bash
cargo test -p neuromesh-integration-tests
cargo test -p agent-ebpf-sensor --lib
cargo test -p agent-ebpf-sensor --test event_parser_fuzz_test
cargo test -p agent-ebpf-sensor --test chaos_engineering_test --features orchestrator
```

### Live (Linux + root)

```bash
cargo build -p agent-ebpf-sensor --features orchestrator --release
sudo -E ./target/release/agent-ebpf-sensor &
./scripts/simulate_attack.sh
curl -s http://127.0.0.1:9090/metrics | grep ebpf_events
```

Policy-bundle signature + temporal fail-closed (valid / corrupt / missing /
tampered / capture-replay expired) — paste-back before merge for T-PB-04:

```bash
export AGENT_BIN=./target/release/agent-ebpf-sensor
sudo -E bash scripts/manual_verify_policy_bundle_signature.sh
```

Expected simulation output:

1. Benign `/bin/ls`, `/bin/cat` — suppressed (no alert)
2. `/tmp/neuromesh-mock-payload.sh` execution — `CRITICAL_ALERT` (T1204)
3. Rapid `/bin/sh` spawn burst — `BEHAVIOR_ALERT` (T1059.004)

---

## 9. Related documents

| Document | Content |
|----------|---------|
| [`adr-001-lsm-vs-tracepoint.md`](architecture-decision-records/adr-001-lsm-vs-tracepoint.md) | Dual-hook design rationale |
| [`performance-baseline.md`](performance-baseline.md) | Latency, drop rate, load-test methodology |
| [`../README.md`](../README.md) | Architecture overview, deployment checklist |

---

*Review this document before each release candidate. Update MITRE mappings when new hooks ship or detection rules change.*
