//! Shared process-event layout and testable event stream abstractions.

use std::collections::VecDeque;
use std::ptr;

/// Kernel/userspace shared layout for `sys_enter_execve` visibility events.
///
/// Memory layout (`#[repr(C)]`, 392 bytes):
/// ```text
/// +0x00  pid     u32
/// +0x04  uid     u32
/// +0x08  argv0   [u8; 128]
/// +0x88  cwd     [u8; 256]
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessEvent {
    pub pid: u32,
    pub uid: u32,
    pub argv0: [u8; 128],
    pub cwd: [u8; 256],
}

unsafe impl aya::Pod for ProcessEvent {}

impl ProcessEvent {
    /// Zero-copy decode from a ring buffer record slice (no heap allocation).
    #[inline]
    pub fn from_bytes_unaligned(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }
}

/// Abstraction over event producers (live RingBuf or unit-test mocks).
pub trait EventStream {
    fn next_event(&mut self) -> Option<ProcessEvent>;
}

/// In-memory injector for unit tests — no eBPF loader required.
#[derive(Default)]
pub struct MockEventStream {
    queue: VecDeque<ProcessEvent>,
}

impl MockEventStream {
    pub fn push(&mut self, event: ProcessEvent) {
        self.queue.push_back(event);
    }
}

impl EventStream for MockEventStream {
    fn next_event(&mut self) -> Option<ProcessEvent> {
        self.queue.pop_front()
    }
}

/// Zero-allocation hot-path observer with rate-limited info logging.
#[derive(Debug, Default)]
pub struct ProcessEventHandler {
    seen: u64,
}

impl ProcessEventHandler {
    pub const INFO_SAMPLE_INTERVAL: u64 = 10_000;

    /// Observe one exec event without heap allocation on the hot path.
    #[inline]
    pub fn observe(&mut self, event: &ProcessEvent) {
        tracing::debug!(
            target: "neuromesh::process_monitor",
            pid = event.pid,
            uid = event.uid,
            "execve event"
        );

        self.seen = self.seen.wrapping_add(1);
        if self.seen.is_multiple_of(Self::INFO_SAMPLE_INTERVAL) {
            tracing::info!(
                target: "neuromesh::process_monitor",
                seen = self.seen,
                sample_pid = event.pid,
                sample_uid = event.uid,
                "process visibility throughput sample"
            );
        }
    }

    pub fn events_seen(&self) -> u64 {
        self.seen
    }
}

/// Drain any stream through the shared hot-path handler (test + production helper).
pub fn drain_events(stream: &mut impl EventStream, handler: &mut ProcessEventHandler) {
    while let Some(event) = stream.next_event() {
        handler.observe(&event);
    }
}

#[cfg(test)]
mod tests {
    use super::{drain_events, EventStream, MockEventStream, ProcessEvent, ProcessEventHandler};
    use core::mem::{offset_of, size_of};

    #[test]
    fn process_event_layout_matches_bpf_struct() {
        assert_eq!(size_of::<ProcessEvent>(), 392);
        assert_eq!(offset_of!(ProcessEvent, argv0), 8);
        assert_eq!(offset_of!(ProcessEvent, cwd), 136);
    }

    fn bytes_with_prefix<const N: usize>(prefix: &[u8]) -> [u8; N] {
        let mut buf = [0u8; N];
        let len = prefix.len().min(N);
        buf[..len].copy_from_slice(&prefix[..len]);
        buf
    }

    #[test]
    fn mock_event_stream_injects_events_without_ebpf() {
        let mut stream = MockEventStream::default();
        let mut handler = ProcessEventHandler::default();

        let event = ProcessEvent {
            pid: 4242,
            uid: 1000,
            argv0: bytes_with_prefix::<128>(b"/bin/ls"),
            cwd: bytes_with_prefix::<256>(b"/tmp"),
        };
        stream.push(event);

        drain_events(&mut stream, &mut handler);
        assert_eq!(handler.events_seen(), 1);
        assert!(stream.next_event().is_none());
    }

    #[test]
    fn from_bytes_unaligned_roundtrip() {
        let event = ProcessEvent {
            pid: 99,
            uid: 1,
            argv0: [0; 128],
            cwd: [0; 256],
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const ProcessEvent as *const u8,
                size_of::<ProcessEvent>(),
            )
        };
        let decoded = ProcessEvent::from_bytes_unaligned(bytes).expect("decode");
        assert_eq!(decoded, event);
    }
}
