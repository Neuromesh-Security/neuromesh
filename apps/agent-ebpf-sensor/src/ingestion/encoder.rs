//! Protobuf encoder with reusable buffer for the async ingestion worker.

use crate::monitoring::EnrichedNetworkEvent;
use neuromesh_proto::{
    EnrichedNetworkEvent as ProtoEnrichedNetworkEvent, ENRICHED_NETWORK_EVENT_SCHEMA_VERSION,
};
use prost::Message;

/// Reuses an internal `Vec<u8>` across serializations to avoid per-message allocations.
#[derive(Debug, Default)]
pub struct ProtobufEncoder {
    buffer: Vec<u8>,
}

impl ProtobufEncoder {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    pub fn encode_enriched_network_event(
        &mut self,
        node_name: &str,
        event_id: &str,
        timestamp_ns: i64,
        event: &EnrichedNetworkEvent,
    ) -> Result<&[u8], prost::EncodeError> {
        self.buffer.clear();

        let message = ProtoEnrichedNetworkEvent {
            schema_version: ENRICHED_NETWORK_EVENT_SCHEMA_VERSION,
            event_id: event_id.to_string(),
            timestamp_ns,
            node_name: node_name.to_string(),
            pid: event.pid,
            uid: event.uid,
            dest_ip: event.dest_ip,
            dest_port: u32::from(event.dest_port),
            process_name: event.process_name.clone(),
        };

        message.encode(&mut self.buffer)?;
        Ok(&self.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_correlated_fields() {
        let mut encoder = ProtobufEncoder::with_capacity(128);
        let event = EnrichedNetworkEvent {
            pid: 4242,
            uid: 1000,
            dest_ip: u32::from_be_bytes([8, 8, 8, 8]),
            dest_port: 443u16.to_be(),
            process_name: "/bin/curl".to_string(),
        };

        let bytes = encoder
            .encode_enriched_network_event("node-a", "node-a-4242-1", 1, &event)
            .expect("encode");

        let decoded = ProtoEnrichedNetworkEvent::decode(bytes).expect("decode");
        assert_eq!(
            decoded.schema_version,
            ENRICHED_NETWORK_EVENT_SCHEMA_VERSION
        );
        assert_eq!(decoded.pid, 4242);
        assert_eq!(decoded.process_name, "/bin/curl");
        assert_eq!(decoded.dest_ip, event.dest_ip);
        assert_eq!(decoded.dest_port, u32::from(event.dest_port));
    }
}
