//! Shared process-event layout and testable event stream abstractions.

use neuromesh_common::ExecEvent;
use std::collections::VecDeque;
use std::ptr;

/// Type alias — `ExecEvent` v1 is the sole kernel/userspace exec visibility record.
pub type ProcessEvent = ExecEvent;

/// Zero-copy decode from a ring buffer record slice (no heap allocation).
#[inline]
pub fn decode_process_event(bytes: &[u8]) -> Option<ExecEvent> {
    crate::monitoring::exec_mapper::decode_exec_event(bytes)
}

/// Abstraction over event producers (live RingBuf or unit-test mocks).
pub trait EventStream {
    fn next_event(&mut self) -> Option<ExecEvent>;
}

/// In-memory injector for unit tests — no eBPF loader required.
#[derive(Default)]
pub struct MockEventStream {
    queue: VecDeque<ExecEvent>,
}

impl MockEventStream {
    pub fn push(&mut self, event: ExecEvent) {
        self.queue.push_back(event);
    }
}

impl EventStream for MockEventStream {
    fn next_event(&mut self) -> Option<ExecEvent> {
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
    pub fn observe(&mut self, event: &ExecEvent) {
        let pid = event.pid;
        let uid = event.uid;
        let ppid = event.ppid;
        tracing::debug!(
            target: "neuromesh::process_monitor",
            pid,
            uid,
            ppid,
            ts = event.timestamp_ns,
            args_count = event.args_count,
            enforcement = event.enforcement_action,
            capture_status = event.capture_status,
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
    use super::{drain_events, EventStream, MockEventStream, ProcessEventHandler};
    use core::mem::{offset_of, size_of};
    use neuromesh_common::{
        ExecEvent, EXEC_EVENT_SCHEMA_VERSION, EXEC_EVENT_STRUCT_SIZE, EXEC_EVENT_TYPE_EXECVE,
        MAX_COMM_LEN, MAX_CONTAINER_ID_LEN, MAX_FILENAME_LEN,
    };

    fn bytes_with_prefix<const N: usize>(prefix: &[u8]) -> [u8; N] {
        let mut buf = [0u8; N];
        let len = prefix.len().min(N);
        buf[..len].copy_from_slice(&prefix[..len]);
        buf
    }

    fn sample_event() -> ExecEvent {
        ExecEvent {
            schema_version: EXEC_EVENT_SCHEMA_VERSION,
            event_type: EXEC_EVENT_TYPE_EXECVE,
            flags: 0,
            struct_size: EXEC_EVENT_STRUCT_SIZE,
            header_reserved: 0,
            header_pad: [0; 8],
            pid: 4242,
            ppid: 1,
            tgid: 4242,
            uid: 1000,
            euid: 1000,
            gid: 1000,
            comm: bytes_with_prefix::<MAX_COMM_LEN>(b"ls"),
            filename: bytes_with_prefix::<MAX_FILENAME_LEN>(b"/bin/ls"),
            args_count: 1,
            container_id: bytes_with_prefix::<MAX_CONTAINER_ID_LEN>(b"host"),
            align_pad: [0; 4],
            namespace_id: 1,
            timestamp_ns: 1_234_567_890,
            enforcement_action: 0,
            capture_status: 0,
            status_reserved: [0; 5],
        }
    }

    #[test]
    fn exec_event_layout_matches_bpf_struct() {
        assert_eq!(size_of::<ExecEvent>(), EXEC_EVENT_STRUCT_SIZE as usize);
        assert_eq!(offset_of!(ExecEvent, comm), 40);
        assert_eq!(offset_of!(ExecEvent, filename), 56);
        assert_eq!(offset_of!(ExecEvent, timestamp_ns), 392);
    }

    #[test]
    fn mock_event_stream_injects_events_without_ebpf() {
        let mut stream = MockEventStream::default();
        let mut handler = ProcessEventHandler::default();
        stream.push(sample_event());
        drain_events(&mut stream, &mut handler);
        assert_eq!(handler.events_seen(), 1);
        assert!(stream.next_event().is_none());
    }

    #[test]
    fn decode_process_event_rejects_truncated_records() {
        assert!(super::decode_process_event(&[0u8; 16]).is_none());
    }

    #[test]
    fn handler_survives_max_field_values() {
        let mut event = sample_event();
        event.pid = u32::MAX;
        event.uid = u32::MAX;
        event.ppid = u32::MAX;
        event.comm = [0xFF; MAX_COMM_LEN];
        event.filename = [0xFF; MAX_FILENAME_LEN];
        event.timestamp_ns = u64::MAX;
        let mut handler = ProcessEventHandler::default();
        handler.observe(&event);
        assert_eq!(handler.events_seen(), 1);
    }

    #[test]
    fn decode_process_event_roundtrip() {
        let event = sample_event();
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const ExecEvent as *const u8,
                size_of::<ExecEvent>(),
            )
        };
        let decoded = super::decode_process_event(bytes).expect("decode");
        assert_eq!(decoded.pid, event.pid);
        assert_eq!(decoded.filename[..7], *b"/bin/ls");
    }
}
