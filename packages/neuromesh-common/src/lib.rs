#![no_std]

/// Maximum buffer size for intercepted file paths in kernel telemetry events.
pub const MAX_FILENAME_LEN: usize = 256;

/// Linux `TASK_COMM_LEN` — process name captured from `task_struct->comm`.
pub const MAX_COMM_LEN: usize = 16;

/// Cgroup / container identifier buffer (cgroup v2 path or kernfs name).
pub const MAX_CONTAINER_ID_LEN: usize = 64;

/// NUL-separated argv is stored as fixed verifier-safe slots:
/// [`MAX_ARGS_CAPTURE`] × [`MAX_ARG_STR_LEN`] = [`MAX_ARGV_LEN`] bytes.
/// Captured at `sys_enter_execve` (Issue #46).
pub const MAX_ARGS_CAPTURE: usize = 8;
pub const MAX_ARG_STR_LEN: usize = 32;
pub const MAX_ARGV_LEN: usize = MAX_ARGS_CAPTURE * MAX_ARG_STR_LEN;

/// Schema revision for `ExecEvent` ring-buffer records.
///
/// v2 adds capped argv payload (`argv` / `argv_len`) — see Issue #46.
pub const EXEC_EVENT_SCHEMA_VERSION: u16 = 2;

/// Event type discriminator — `execve` syscall visibility.
///
/// Every exec record carries this value regardless of which syscall produced it;
/// the variant is reported through [`ExecEvent::flags`] instead. See
/// [`EXEC_FLAG_SYSCALL_EXECVEAT`].
pub const EXEC_EVENT_TYPE_EXECVE: u8 = 1;

/// [`ExecEvent::flags`]: record came from `sys_enter_execveat`, not
/// `sys_enter_execve` (Issue #126).
///
/// Covers both `execveat(2)` and `fexecve(3)` — glibc implements the latter as
/// `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`, so there is no distinct
/// `fexecve` syscall to trace.
pub const EXEC_FLAG_SYSCALL_EXECVEAT: u8 = 1 << 0;

/// [`ExecEvent::flags`]: the exec target was named by a file descriptor
/// (`AT_EMPTY_PATH`), so no path string was available at the tracepoint.
///
/// `filename` holds [`UNKNOWN_SENTINEL`] and [`CAPTURE_FILENAME`] is raised.
/// Distinguishes an fd-named exec from a probe fault.
pub const EXEC_FLAG_PATH_FROM_FD: u8 = 1 << 1;

/// Serialized size of `ExecEvent` v2 (fixed for verifier + userspace bounds checks).
pub const EXEC_EVENT_STRUCT_SIZE: u16 = 668;

/// Maximum argv pointers probed / slots filled when capturing arguments.
pub const MAX_ARGS_PROBE: u32 = MAX_ARGS_CAPTURE as u32;

/// Telemetry visibility — syscall observed, not denied by LSM.
pub const ENFORCEMENT_ALLOWED: u8 = 0;

/// LSM denied execution before binary load.
pub const ENFORCEMENT_BLOCKED: u8 = 1;

/// Enforcement outcome could not be determined.
pub const ENFORCEMENT_UNKNOWN: u8 = 2;

/// Per-field capture failure bits in `ExecEvent::capture_status`.
pub const CAPTURE_PID: u16 = 1 << 0;
pub const CAPTURE_PPID: u16 = 1 << 1;
pub const CAPTURE_TGID: u16 = 1 << 2;
pub const CAPTURE_UID: u16 = 1 << 3;
pub const CAPTURE_EUID: u16 = 1 << 4;
pub const CAPTURE_GID: u16 = 1 << 5;
pub const CAPTURE_COMM: u16 = 1 << 6;
pub const CAPTURE_FILENAME: u16 = 1 << 7;
pub const CAPTURE_ARGS_COUNT: u16 = 1 << 8;
pub const CAPTURE_CONTAINER_ID: u16 = 1 << 9;
pub const CAPTURE_NAMESPACE_ID: u16 = 1 << 10;
pub const CAPTURE_TIMESTAMP: u16 = 1 << 11;
/// Argv string copy truncated, faulted, or unavailable (Issue #46).
pub const CAPTURE_ARGV: u16 = 1 << 12;

/// Sentinel written by the kernel when a string field cannot be captured.
pub const UNKNOWN_SENTINEL: &[u8] = b"UNKNOWN";

/// Argv argc overflow: more than [`MAX_ARGS_CAPTURE`] pointers were present.
pub const ARGV_FLAG_ARGC_TRUNCATED: u8 = 1 << 0;
/// Argv probe fault (null argv / read error) distinct from length truncation.
pub const ARGV_FLAG_PROBE_FAULT: u8 = 1 << 1;

/// Enterprise exec visibility record — shared between C BPF and user-space consumers.
///
/// `schema_version` is written last in the kernel hot path so partially-written
/// records are rejected by user-space decoders.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ExecEvent {
    pub schema_version: u16,
    pub event_type: u8,
    pub flags: u8,
    pub struct_size: u16,
    pub header_reserved: u16,
    pub header_pad: [u8; 8],
    pub pid: u32,
    pub ppid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    pub args_count: u32,
    /// Number of successfully copied argv slots (0..=[`MAX_ARGS_CAPTURE`]).
    pub argv_len: u16,
    /// Bit `i` set when slot `i` filled the 32-byte buffer (argument may be truncated).
    pub argv_trunc_mask: u8,
    /// [`ARGV_FLAG_ARGC_TRUNCATED`] / [`ARGV_FLAG_PROBE_FAULT`].
    pub argv_flags: u8,
    /// Argv storage: [`MAX_ARGS_CAPTURE`] × [`MAX_ARG_STR_LEN`] fixed slots
    /// (flat `[u8; MAX_ARGV_LEN]`).
    pub argv: [u8; MAX_ARGV_LEN],
    pub container_id: [u8; MAX_CONTAINER_ID_LEN],
    pub align_pad: [u8; 4],
    pub namespace_id: u64,
    pub timestamp_ns: u64,
    pub enforcement_action: u8,
    pub capture_status: u16,
    pub status_reserved: [u8; 5],
}

impl ExecEvent {
    /// Validate header invariants before trusting field contents.
    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.schema_version == EXEC_EVENT_SCHEMA_VERSION
            && self.event_type == EXEC_EVENT_TYPE_EXECVE
            && self.struct_size == EXEC_EVENT_STRUCT_SIZE
    }

    /// Returns true when the capture_status bit for `field` is raised.
    #[inline]
    pub const fn field_unknown(&self, field: u16) -> bool {
        self.capture_status & field != 0
    }

    /// True when this record came from `execveat(2)` or `fexecve(3)` rather than
    /// `execve(2)` (Issue #126).
    #[inline]
    pub const fn is_execveat(&self) -> bool {
        self.flags & EXEC_FLAG_SYSCALL_EXECVEAT != 0
    }

    /// True when the exec target was named by a file descriptor (`AT_EMPTY_PATH`),
    /// so `filename` carries [`UNKNOWN_SENTINEL`] rather than a real path.
    #[inline]
    pub const fn path_from_fd(&self) -> bool {
        self.flags & EXEC_FLAG_PATH_FROM_FD != 0
    }
}

/// Memory-aligned, C-compatible telemetry record shared between Ring 0 and user space.
///
/// Canonical downstream format for rule engines and SIEM pipelines. Populated via
/// `ExecEvent` → `SecurityTelemetryEvent` mapping in the agent orchestrator.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SecurityTelemetryEvent {
    pub pid: u32,
    pub ppid: u32,
    /// True when kernel lineage capture failed (`CAPTURE_PPID`): `ppid` is then
    /// `0` as a sentinel and must not be treated as a real parent id. Burst
    /// detection keys these events by `comm` instead (Issue #132).
    pub ppid_unresolved: bool,
    pub uid: u32,
    pub euid: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    pub argv_len: u16,
    /// True when any argv slot was buffer-full / argc overflowed / probe faulted.
    pub argv_truncated: bool,
    pub argv_trunc_mask: u8,
    pub argv: [u8; MAX_ARGV_LEN],
}

/// Kernel/user-space health counters exposed via the `TELEMETRY_STATS` BPF array map.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TelemetryHealthStats {
    pub events_processed: u64,
    pub lost_events_count: u64,
}

/// Single-slot index for the `TELEMETRY_STATS` array map.
pub const TELEMETRY_STATS_INDEX: u32 = 0;

/// Max path-prefix deny entries in the LSM `PATH_DENY_LIST` BPF array.
///
/// Bound is fixed for the BPF verifier (compile-time-bounded loop). 64 is far
/// above the Phase-1 bootstrap set of 3 while remaining a trivial hot-path cost.
pub const PATH_DENY_MAX_ENTRIES: u32 = 64;

/// Byte length of each deny-list prefix key — matches the LSM's
/// `PATH_PREFIX_LEN` window used for blacklist matching.
pub const PATH_DENY_KEY_BYTES: usize = 16;

/// Kernel `BPF_OBJ_NAME_LEN` is 16 (including NUL) → max usable object name length.
///
/// Map and program names longer than this are truncated (or rejected by bpftool
/// name lookup). All Neuromesh BPF object names MUST be ≤ this length.
pub const BPF_OBJ_NAME_MAX: usize = 15;

/// Compile-time guard: reject BPF object names that exceed [`BPF_OBJ_NAME_MAX`].
pub const fn bpf_obj_name(name: &'static str) -> &'static str {
    assert!(name.len() <= BPF_OBJ_NAME_MAX);
    name
}

/// BPF map name for the centrally-governed path-prefix deny list (enforcement object).
pub const PATH_DENY_LIST_MAP: &str = bpf_obj_name("PATH_DENY_LIST");

/// BPF map name for the active entry count companion array (single u32 at index 0).
pub const PATH_DENY_COUNT_MAP: &str = bpf_obj_name("PATH_DENY_COUNT");

/// Bootstrap / fail-closed default deny prefixes — identical to the historical
/// hardcoded LSM set (`/tmp/`, `/dev/shm/`, `/var/tmp/`). Must stay in sync with
/// `zt-policy-engine`'s `/v1/policy-bundle` export.
pub const BOOTSTRAP_PATH_DENY_PREFIXES: &[&[u8]] = &[b"/tmp/", b"/dev/shm/", b"/var/tmp/"];

/// Max entries in `ID_ALLOW_CGROUP`.
///
/// Slice 2b-ii keys **one entry per container-leaf cgroup** (not one per pod).
/// Typical allowlisted service-mesh pods run ~2–4 containers (app + sidecar ±
/// init); 16384 restores ~4096-pod equivalent headroom at N≈4 while keeping
/// the BPF `HashMap<u64,u8>` under ~1–1.4 MiB prealloc (see 2b-ii capacity
/// decision). Only PE-allowlisted workloads on this node are inserted.
pub const IDENTITY_ALLOW_CGROUPS_MAX_ENTRIES: u32 = 16384;

/// BPF map: cgroup_id → allow (`1` = excepted for `/tmp/` when VALID=1).
/// Kernel name ≤15 (`IDENTITY_ALLOW_CGROUPS` exceeded `BPF_OBJ_NAME_LEN`).
pub const IDENTITY_ALLOW_CGROUPS_MAP: &str = bpf_obj_name("ID_ALLOW_CGROUP");

/// BPF map: single-slot freshness flag for identity exceptions.
/// Kernel name ≤15 (`IDENTITY_EXCEPTIONS_VALID` exceeded `BPF_OBJ_NAME_LEN`).
pub const IDENTITY_EXCEPTIONS_VALID_MAP: &str = bpf_obj_name("ID_EXCEPT_VALID");

/// Value written into `ID_ALLOW_CGROUP` for an allowed cgroup.
pub const IDENTITY_ALLOW_VALUE: u8 = 1;

/// `ID_EXCEPT_VALID[0]` when the PE identity section is fresh.
pub const IDENTITY_EXCEPTIONS_VALID_FRESH: u8 = 1;

/// `ID_EXCEPT_VALID[0]` when stale/missing/invalid — no exceptions.
pub const IDENTITY_EXCEPTIONS_VALID_STALE: u8 = 0;

/// Process-visibility ringbuf (C `sys_exec.bpf.c`).
pub const PROCESS_EVENTS_MAP: &str = bpf_obj_name("PROCESS_EVENTS");

/// Per-CPU token-bucket state (C `sys_exec.bpf.c`). Was `RATE_LIMIT_BUCKET` (17).
pub const RATE_LIMIT_BUCKET_MAP: &str = bpf_obj_name("RLIMIT_BUCKET");

/// Per-CPU rate-limit drop counter (C `sys_exec.bpf.c`). Was `RATE_LIMIT_DROPS` (16).
pub const RATE_LIMIT_DROPS_MAP: &str = bpf_obj_name("RLIMIT_DROPS");

/// Filename-capture failure counter (C `sys_exec.bpf.c`). Was `CAPTURE_FAILURES` (16).
pub const CAPTURE_FAILURES_MAP: &str = bpf_obj_name("CAPTURE_FAILS");

/// Network visibility ringbuf (C `network_filter.bpf.c`).
pub const NETWORK_EVENTS_MAP: &str = bpf_obj_name("NETWORK_EVENTS");

/// Network ringbuf drop counter (C `network_filter.bpf.c`).
pub const DROPPED_EVENTS_MAP: &str = bpf_obj_name("DROPPED_EVENTS");

/// LSM enforcement telemetry ringbuf (Rust eBPF). Was `TELEMETRY_RINGBUF` (16).
pub const TELEMETRY_RINGBUF_MAP: &str = bpf_obj_name("TELEM_RINGBUF");

/// LSM telemetry health counters array (Rust eBPF).
pub const TELEMETRY_STATS_MAP: &str = bpf_obj_name("TELEMETRY_STATS");

/// LSM deny program (Rust eBPF). Was `neuromesh_lsm_exec_guard` (24).
pub const LSM_EXEC_GUARD_PROG: &str = bpf_obj_name("nm_lsm_bprm");

/// Process visibility program (C). Was `neuromesh_process_events` (24).
pub const PROCESS_EVENTS_PROG: &str = bpf_obj_name("nm_proc_events");

/// `execveat`/`fexecve` visibility program (C), Issue #126. Shares
/// `PROCESS_EVENTS` and `RLIMIT_BUCKET` with [`PROCESS_EVENTS_PROG`].
pub const PROCESS_EVENTS_AT_PROG: &str = bpf_obj_name("nm_execveat");

/// TCP connect visibility program (C). Was `neuromesh_tcp_connect` (20).
pub const TCP_CONNECT_PROG: &str = bpf_obj_name("nm_tcp_connect");

/// Every BPF map/prog object name shipped by Neuromesh (for collision lint).
pub const ALL_BPF_OBJECT_NAMES: &[&str] = &[
    PATH_DENY_LIST_MAP,
    PATH_DENY_COUNT_MAP,
    IDENTITY_ALLOW_CGROUPS_MAP,
    IDENTITY_EXCEPTIONS_VALID_MAP,
    PROCESS_EVENTS_MAP,
    RATE_LIMIT_BUCKET_MAP,
    RATE_LIMIT_DROPS_MAP,
    CAPTURE_FAILURES_MAP,
    NETWORK_EVENTS_MAP,
    DROPPED_EVENTS_MAP,
    TELEMETRY_RINGBUF_MAP,
    TELEMETRY_STATS_MAP,
    LSM_EXEC_GUARD_PROG,
    PROCESS_EVENTS_PROG,
    PROCESS_EVENTS_AT_PROG,
    TCP_CONNECT_PROG,
];

/// Only path prefix eligible for identity exceptions (must match PE export).
pub const IDENTITY_EXCEPTION_SCOPE_PREFIX: &[u8] = b"/tmp/";

/// One deny-list entry stored in the `PATH_DENY_LIST` BPF array.
///
/// `len` is the significant byte count in `bytes` (1..=PATH_DENY_KEY_BYTES).
/// Matching uses the same `starts_with` semantics as the former hardcoded LSM
/// compare: the path is denied iff it begins with `bytes[..len]`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PathDenyEntry {
    pub len: u32,
    pub bytes: [u8; PATH_DENY_KEY_BYTES],
}

impl PathDenyEntry {
    /// Build an entry from a path prefix. Returns `None` if empty or longer
    /// than [`PATH_DENY_KEY_BYTES`].
    pub fn from_prefix(prefix: &[u8]) -> Option<Self> {
        if prefix.is_empty() || prefix.len() > PATH_DENY_KEY_BYTES {
            return None;
        }
        let mut bytes = [0u8; PATH_DENY_KEY_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix);
        Some(Self {
            len: prefix.len() as u32,
            bytes,
        })
    }

    /// True when `path` starts with this entry's significant bytes.
    #[inline]
    pub fn matches(&self, path: &[u8]) -> bool {
        let len = self.len as usize;
        if len == 0 || len > PATH_DENY_KEY_BYTES || path.len() < len {
            return false;
        }
        path[..len]
            .iter()
            .zip(self.bytes[..len].iter())
            .all(|(a, b)| a == b)
    }
}

impl Default for PathDenyEntry {
    fn default() -> Self {
        Self {
            len: 0,
            bytes: [0; PATH_DENY_KEY_BYTES],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SecurityTelemetryEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TelemetryHealthStats {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PathDenyEntry {}

#[cfg(test)]
mod bpf_obj_name_tests {
    use super::*;

    #[test]
    fn all_bpf_object_names_fit_and_are_unique_under_truncation() {
        let mut seen = [None; ALL_BPF_OBJECT_NAMES.len()];
        for (i, name) in ALL_BPF_OBJECT_NAMES.iter().enumerate() {
            assert!(
                name.len() <= BPF_OBJ_NAME_MAX,
                "{name:?} len {} > {BPF_OBJ_NAME_MAX}",
                name.len()
            );
            let trunc = if name.len() > BPF_OBJ_NAME_MAX {
                &name[..BPF_OBJ_NAME_MAX]
            } else {
                name
            };
            for (j, prev) in seen.iter().enumerate().take(i) {
                if let Some(p) = prev {
                    assert_ne!(
                        trunc, *p,
                        "truncation collision: {name:?} vs earlier name sharing {trunc:?} (index {j})"
                    );
                }
            }
            seen[i] = Some(trunc);
        }
    }
}
