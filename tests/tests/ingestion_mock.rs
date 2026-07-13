//! Integration tests for correlation ingestion channel pressure and protobuf integrity.

use agent_ebpf_sensor::ingestion::{
    CorrelationIngestionConfig, CorrelationIngestionHandle, ProtobufEncoder,
    PRESSURE_DROP_THRESHOLD_PCT,
};
use agent_ebpf_sensor::monitoring::EnrichedNetworkEvent;
use neuromesh_proto::{
    EnrichedNetworkEvent as ProtoEnrichedNetworkEvent, ENRICHED_NETWORK_EVENT_SCHEMA_VERSION,
};
use prost::Message;

fn sample_event() -> EnrichedNetworkEvent {
    EnrichedNetworkEvent {
        pid: 4242,
        uid: 1000,
        dest_ip: u32::from_be_bytes([203, 0, 113, 1]),
        dest_port: 443u16.to_be(),
        process_name: "/usr/bin/curl".to_string(),
    }
}

#[test]
fn protobuf_roundtrip_preserves_network_and_process_identity() {
    let mut encoder = ProtobufEncoder::with_capacity(256);
    let event = sample_event();

    let bytes = encoder
        .encode_enriched_network_event("sensor-a", "sensor-a-4242-99", 99, &event)
        .expect("encode");

    let decoded = ProtoEnrichedNetworkEvent::decode(bytes).expect("decode");
    assert_eq!(
        decoded.schema_version,
        ENRICHED_NETWORK_EVENT_SCHEMA_VERSION
    );
    assert_eq!(decoded.node_name, "sensor-a");
    assert_eq!(decoded.pid, 4242);
    assert_eq!(decoded.uid, 1000);
    assert_eq!(decoded.dest_ip, event.dest_ip);
    assert_eq!(decoded.dest_port, u32::from(event.dest_port));
    assert_eq!(decoded.process_name, "/usr/bin/curl");
}

#[test]
fn channel_pressure_drops_at_ninety_percent_capacity() {
    let config = CorrelationIngestionConfig {
        brokers: String::new(),
        topic: String::new(),
        node_name: "sensor-a".to_string(),
        channel_capacity: 20,
    };
    assert_eq!(
        config.pressure_drop_threshold(),
        20 * PRESSURE_DROP_THRESHOLD_PCT / 100
    );

    let (handle, _rx) = CorrelationIngestionHandle::new_for_test(config);
    handle.stats().testing_set_queued(18);

    handle.try_enqueue(sample_event());
    assert_eq!(handle.stats().dropped_events(), 1);
    assert_eq!(handle.stats().enqueued(), 0);
}

#[tokio::test]
async fn channel_accepts_events_below_pressure_threshold() {
    let config = CorrelationIngestionConfig {
        brokers: String::new(),
        topic: String::new(),
        node_name: "sensor-a".to_string(),
        channel_capacity: 20,
    };

    let (handle, mut rx) = CorrelationIngestionHandle::new_for_test(config);
    handle.stats().testing_set_queued(5);

    handle.try_enqueue(sample_event());
    assert_eq!(handle.stats().enqueued(), 1);
    assert_eq!(handle.stats().dropped_events(), 0);

    let received = rx.recv().await.expect("event");
    assert_eq!(received.pid, 4242);
    assert_eq!(received.process_name, "/usr/bin/curl");
}
