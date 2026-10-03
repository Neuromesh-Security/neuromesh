# ADR-002: Pinned BPF Map ABI Versioning and Migration

**Status:** Accepted  
**Date:** 2026-10-03  
**Context:** Neuromesh agent CrashLoop on lab droplet after deploying
`@sha256:bcb82764…` (main `c6393e0` / PR #206). Tracking: Issue #208.

## Context

Enforcement maps (`PATH_DENY_LIST`, `PATH_DENY_COUNT`) and visibility maps
(`PROCESS_EVENTS`, `RLIMIT_BUCKET`) are pinned under bpffs so deny policy and
visibility state survive agent exit (Issue #44 / PR #72).

aya 0.14 `MapData::create_pinned_by_name` opens an existing pin with
`bpf_get_object` and **reuses the FD without comparing** `map_type`,
`key_size`, `value_size`, or `max_entries` to the object being loaded.

PR #134 raised `PATH_DENY_KEY_BYTES` from 16 → 32 (`PathDenyEntry` 20 → 36
bytes). A node that still held pre-#134 pins caused the verifier to reject
`nm_lsm_bprm`:

```text
invalid access to map value, value_size=20 off=20 size=1
```

Fail-closed refused to start (correct), but the old LSM link pin kept the
stale program attached. The node stayed **safe but unavailable** with no
self-heal.

## Decision

**(e) Validate and migrate** pinned map ABI before `EbpfLoader::load`.

1. `ENFORCEMENT_PIN_ABI_VERSION` + `PINNED_MAP_ABI` live in `neuromesh-common`
   (single source of truth; compile-time layout asserts; golden test forces a
   version bump on layout change).
2. Userspace `pin_abi::reconcile_pinned_map_abi` runs **before** load and
   returns `Cold | Compatible | LegacyMigratable | Incompatible |
   MigrationInProgress`.
3. For the known 16→32 deny-list layout (`value_size == 20`):
   - Read legacy entries read-only.
   - `rename` map pins into `<pin_root>/legacy_abi_<n>/` (no `.` in names —
     bpffs `-EPERM` on dotted basenames). **Leave the LSM link pin in place**
     so the old program keeps enforcing (F2).
   - Load creates fresh maps at canonical names; seed widened entries
     (zero-pad to 32) or bootstrap if legacy is unreadable (never empty — F3).
   - Attach via existing `attach_and_pin_lsm_fail_closed` (tmp → swap).
   - Delete `legacy_abi_<n>` only after the new link is pinned and re-opened.
4. Unknown layouts are refused with an actionable error (F4) — never coerced.
5. Process maps (`PINNED_PROCESS_MAPS`) get the same ABI check. On mismatch they
   are renamed aside / recreated: they hold **no enforcement state** (ringbuf +
   rate-limit counters only). Log loudly.
6. Crash safety: `legacy_abi_*` ⇒ `MigrationInProgress` (not
   `InconsistentLinkWithoutMaps`). Re-runs are idempotent. `kill -9` at any
   step recovers on the next start without an empty deny list.

## Alternatives considered

| Option | Verdict |
|--------|---------|
| (a) Revert `PATH_DENY_KEY_BYTES` to 16 | **Rejected** — ABI regression; does not fix the class of bug |
| (b) Wipe pins on every start | **Rejected** — destroys pin-survival and tamper-evidence (Issue #44) |
| (c) Detect and refuse only | Minimum viable, no self-heal — lab stays stuck until manual pin rm (enforcement gap) |
| (d) Versioned pin namespace always | Heavier; migration still required for in-place clusters |
| (e) Validate + migrate | **Accepted** — satisfies F1–F5 |

## Consequences

### Positive

- Post-#134 agents self-heal across the known layout bump without operator
  `rm` on production nodes.
- Future ABI changes must bump `ENFORCEMENT_PIN_ABI_VERSION` (golden test).
- Old LSM stays attached until the new link is live — no deliberate
  enforcement gap during migration.

### Negative / trade-offs

- Migration code path must stay crash-safe and tested (unit + droplet script).
- Operators must still know the emergency pin-rm procedure for **unknown**
  layouts (see `docs/runbooks/agent-pin-recovery.md`).
- Process-map recreation loses rate-limit / ringbuf history (acceptable;
  non-enforcement).

## Invariants (non-negotiable)

- **F1** Any error → non-zero exit; never fall back to unpinned/empty/guessed state.
- **F2** No enforcement gap: old `bprm_check_security` stays attached until the new link is pinned.
- **F3** Deny list never empty; resume with `count == 0` still refuses.
- **F4** Unknown layouts refused, never coerced.
- **F5** Integrity monitor `reason=pinned_map` still detects attacker pin deletion; legitimate migration must not false-alarm.
