//! Ring 0 process visibility consumers (tracepoint → RingBuf → userspace).

pub mod process_monitor;

pub use process_monitor::{start_process_monitor, ProcessEvent};
