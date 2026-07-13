//! Ring 0 process visibility consumers (tracepoint → RingBuf → userspace).

pub mod event;

#[cfg(feature = "orchestrator")]
mod process_monitor;

pub use event::{drain_events, EventStream, MockEventStream, ProcessEvent, ProcessEventHandler};

#[cfg(feature = "orchestrator")]
pub use process_monitor::start_process_monitor;
