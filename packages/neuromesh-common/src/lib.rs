#![no_std]

/// Maximum buffer size for intercepted file paths in kernel telemetry events.
pub const MAX_FILENAME_LEN: usize = 256;

/// Linux `TASK_COMM_LEN` — process name captured from `task_struct->comm`.
pub const MAX_COMM_LEN: usize = 16;

/// Cgroup / container identifier buffer (cgroup v2 path or kernfs name).
pub const MAX_CONTAINER_ID_LEN: usize = 64;

/// Schema revision for `ExecEvent` ring-buffer records.
pub const EXEC_EVENT_SCHEMA_VERSION: u16 = 1;

/// Event type discriminator — `execve` syscall visibility.
pub const EXEC_EVENT_TYPE_EXECVE: u8 = 1;

/// Serialized size of `ExecEvent` v1 (fixed for verifier + userspace bounds checks).
pub const EXEC_EVENT_STRUCT_SIZE: u16 = 408;

/// Maximum argv pointers probed when counting execution arguments.
pub const MAX_ARGS_PROBE: u32 = 16;

/// Passive visibility — syscall observed, not denied by LSM.
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

/// Sentinel written by the kernel when a string field cannot be captured.
pub const UNKNOWN_SENTINEL: &[u8] = b"UNKNOWN";

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
    pub uid: u32,
    pub euid: u32,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SecurityTelemetryEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TelemetryHealthStats {}
