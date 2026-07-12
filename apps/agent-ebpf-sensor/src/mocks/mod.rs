//! Test doubles for eBPF RingBuf and map inputs — no Linux kernel required.

mod ringbuf;
mod telemetry_source;

pub use ringbuf::MockRingBuf;
pub use telemetry_source::{StaticTelemetrySource, TelemetrySource};
