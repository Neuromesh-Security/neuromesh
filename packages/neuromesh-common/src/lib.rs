#![no_std]

/// Maximum buffer size for intercepted file paths in kernel telemetry events.
pub const MAX_FILENAME_LEN: usize = 256;

/// Memory-aligned, C-compatible telemetry record shared between Ring 0 and user space.
///
/// Layout is identical in eBPF (`bpfel-unknown-none`) and the async orchestrator so
/// events can be zero-copied from the RingBuf without deserialization overhead.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecurityTelemetryEvent {
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; MAX_FILENAME_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SecurityTelemetryEvent {}
