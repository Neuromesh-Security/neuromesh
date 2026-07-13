//! Shared process-event layout and testable event stream abstractions.

use std::collections::VecDeque;
use std::ptr;

/// Kernel/userspace shared layout for `sys_enter_execve` visibility events.
///
/// Memory layout (`#[repr(C)]`, 168 bytes):
/// ```text
/// +0x00  pid       u32
/// +0x04  uid       u32
/// +0x08  ppid      u32
/// +0x0C  comm      [u8; 16]
/// +0x1C  filename  [u8; 128]
/// +0xA0  ts        u64
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessEvent {
    pub pid: u32,
    pub uid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
    pub ts: u64,
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
        let pid = event.pid;
        let uid = event.uid;
        let ppid = event.ppid;
        tracing::debug!(
            target: "neuromesh::process_monitor",
            pid,
            uid,
            ppid,
            ts = event.ts,
            "execve event"
        );

        self.seen = self.seen.wrapping_add(1);
        if self.seen.is_multiple_of(Self::INFO_SAMPLE_INTERVAL) {
            tracing::info!(
                target: "neuromesh::process_monitor",
                seen = self.seen,
                sample_pid = pid,
                sample_uid = uid,
                sample_ppid = ppid,
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
        assert_eq!(size_of::<ProcessEvent>(), 168);
        assert_eq!(offset_of!(ProcessEvent, comm), 12);
        assert_eq!(offset_of!(ProcessEvent, filename), 28);
        assert_eq!(offset_of!(ProcessEvent, ts), 160);
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
            ppid: 1,
            comm: bytes_with_prefix::<16>(b"ls"),
            filename: bytes_with_prefix::<128>(b"/bin/ls"),
            ts: 1_234_567_890,
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
            ppid: 42,
            comm: [0; 16],
            filename: [0; 128],
            ts: 99,
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
