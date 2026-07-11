#![no_std]

/// Maximum buffer size for intercepted file paths in kernel telemetry events.
pub const MAX_FILENAME_LEN: usize = 256;

/// Linux `TASK_COMM_LEN` — process name captured from `task_struct->comm`.
pub const MAX_COMM_LEN: usize = 16;

/// Memory-aligned, C-compatible telemetry record shared between Ring 0 and user space.
///
/// Layout is identical in eBPF (`bpfel-unknown-none`) and the async orchestrator so
/// events can be zero-copied from the RingBuf without deserialization overhead.
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
#[derive(Clone, Copy, Default)]
pub struct TelemetryHealthStats {
    pub events_processed: u64,
    pub lost_events_count: u64,
}

/// Single-slot index for the `TELEMETRY_STATS` array map.
pub const TELEMETRY_STATS_INDEX: u32 = 0;

#[cfg(feature = "user")]
unsafe impl aya::Pod for SecurityTelemetryEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TelemetryHealthStats {}
