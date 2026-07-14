//! Ring 0 visibility consumers (eBPF → RingBuf → userspace).

pub mod correlation;
pub mod event;
pub mod network_event;
pub mod ringbuf_decode;

#[cfg(feature = "orchestrator")]
mod network_monitor;

#[cfg(feature = "orchestrator")]
mod process_monitor;

pub use correlation::{CorrelationEngine, EnrichedNetworkEvent};
pub use event::{drain_events, EventStream, MockEventStream, ProcessEvent, ProcessEventHandler};
pub use network_event::{NetworkEvent, NetworkEventHandler};

#[cfg(feature = "orchestrator")]
pub use network_monitor::start_network_monitor;

#[cfg(feature = "orchestrator")]
pub use process_monitor::start_process_monitor;
