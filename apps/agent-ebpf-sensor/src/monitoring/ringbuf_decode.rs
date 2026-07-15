//! Safe zero-copy decoders for RingBuf records (shared by monitors and fuzz tests).

use crate::monitoring::event::decode_process_event;
use crate::monitoring::network_event::NetworkEvent;
use neuromesh_common::ExecEvent;

/// Decode a process visibility record without panicking on short or malformed slices.
#[inline]
pub fn decode_exec_event(bytes: &[u8]) -> Option<ExecEvent> {
    decode_process_event(bytes)
}

/// Decode a network visibility record without panicking on short or malformed slices.
#[inline]
pub fn decode_network_event(bytes: &[u8]) -> Option<NetworkEvent> {
    NetworkEvent::from_bytes_unaligned(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;
    use neuromesh_common::ExecEvent;

    #[test]
    fn decode_exec_event_rejects_short_buffers() {
        assert!(decode_exec_event(&[]).is_none());
        assert!(decode_exec_event(&[0u8; size_of::<ExecEvent>() - 1]).is_none());
    }

    #[test]
    fn decode_network_event_rejects_short_buffers() {
        assert!(decode_network_event(&[]).is_none());
        assert!(decode_network_event(&[0u8; size_of::<NetworkEvent>() - 1]).is_none());
    }
}
