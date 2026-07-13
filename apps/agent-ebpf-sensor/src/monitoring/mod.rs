//! Ring 0 visibility consumers (eBPF → RingBuf → userspace).

pub mod event;
pub mod network_event;

#[cfg(feature = "orchestrator")]
mod network_monitor;

#[cfg(feature = "orchestrator")]
mod process_monitor;

pub use event::{drain_events, EventStream, MockEventStream, ProcessEvent, ProcessEventHandler};
pub use network_event::{NetworkEvent, NetworkEventHandler};

#[cfg(feature = "orchestrator")]
pub use network_monitor::start_network_monitor;

#[cfg(feature = "orchestrator")]
pub use process_monitor::start_process_monitor;
