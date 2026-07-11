#![no_std]

// Defines the maximum buffer size for intercepted file paths
pub const MAX_FILENAME_LEN: usize = 256;

/// Raw telemetry event intercepted directly from the kernel tracepoint.
/// Explicitly aligned using #[repr(C)] to guarantee identical byte layout
/// between the eBPF space and the asynchronous user-space orchestrator.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveTelemetryEvent {
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; MAX_FILENAME_LEN],
}

// Implement the Pod (Plain Old Data) trait for zero-copy deserialization in user-space
#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecveTelemetryEvent {}
