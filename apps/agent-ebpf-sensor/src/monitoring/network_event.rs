//! Shared network-event layout for `tcp_connect` visibility events.

use std::ptr;

/// Kernel/userspace shared layout for `tcp_connect` visibility events.
///
/// Memory layout (`#[repr(C, packed)]`, 14 bytes):
/// ```text
/// +0x00  pid        u32
/// +0x04  uid        u32
/// +0x08  dest_ip    u32  (IPv4, network byte order)
/// +0x0C  dest_port  u16  (network byte order)
/// ```
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub dest_ip: u32,
    pub dest_port: u16,
}

unsafe impl aya::Pod for NetworkEvent {}

impl NetworkEvent {
    /// Zero-copy decode from a ring buffer record slice (no heap allocation).
    #[inline]
    pub fn from_bytes_unaligned(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }

    /// Field accessors safe for packed layout (no unaligned references).
    #[inline]
    pub fn fields(&self) -> (u32, u32, u32, u16) {
        let base = self as *const Self as *const u8;
        unsafe {
            (
                ptr::read_unaligned(base.cast::<u32>()),
                ptr::read_unaligned(base.add(4).cast::<u32>()),
                ptr::read_unaligned(base.add(8).cast::<u32>()),
                ptr::read_unaligned(base.add(12).cast::<u16>()),
            )
        }
    }
}

/// Zero-allocation hot-path observer with rate-limited info logging.
#[derive(Debug, Default)]
pub struct NetworkEventHandler {
    seen: u64,
}

impl NetworkEventHandler {
    pub const INFO_SAMPLE_INTERVAL: u64 = 10_000;

    /// Observe one connect event without heap allocation on the hot path.
    #[inline]
    pub fn observe(&mut self, event: NetworkEvent) {
        let (pid, uid, dest_ip, dest_port) = event.fields();
        tracing::debug!(
            target: "neuromesh::network_monitor",
            pid,
            uid,
            dest_ip,
            dest_port,
            "tcp_connect event"
        );

        self.seen = self.seen.wrapping_add(1);
        if self.seen.is_multiple_of(Self::INFO_SAMPLE_INTERVAL) {
            tracing::info!(
                target: "neuromesh::network_monitor",
                seen = self.seen,
                sample_pid = pid,
                sample_uid = uid,
                sample_dest_ip = dest_ip,
                sample_dest_port = dest_port,
                "network visibility throughput sample"
            );
        }
    }

    pub fn events_seen(&self) -> u64 {
        self.seen
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkEvent, NetworkEventHandler};
    use core::mem::{offset_of, size_of};

    #[test]
    fn network_event_layout_matches_bpf_struct() {
        assert_eq!(size_of::<NetworkEvent>(), 14);
        assert_eq!(offset_of!(NetworkEvent, uid), 4);
        assert_eq!(offset_of!(NetworkEvent, dest_ip), 8);
        assert_eq!(offset_of!(NetworkEvent, dest_port), 12);
    }

    #[test]
    fn handler_observes_packed_event_without_field_refs() {
        let mut handler = NetworkEventHandler::default();
        let event = NetworkEvent {
            pid: 100,
            uid: 1000,
            dest_ip: 0x08080808,
            dest_port: 443,
        };
        handler.observe(event);
        assert_eq!(handler.events_seen(), 1);
    }
}
