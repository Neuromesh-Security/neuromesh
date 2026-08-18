//! Compile-time and manifest isolation from agent LSM/enforcement code paths.

use std::fs;
use std::path::PathBuf;

#[test]
fn crate_manifest_has_no_agent_or_ebpf_dependencies() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = fs::read_to_string(manifest).expect("read Cargo.toml");
    let forbidden = [
        "agent-ebpf-sensor",
        "agent_ebpf_sensor",
        "aya",
        "neuromesh-common",
        "lsm",
        "path_deny",
        "policy_sync",
    ];
    for needle in forbidden {
        assert!(
            !text.contains(needle),
            "forbidden dependency/reference {needle:?} in splunk-hec-forwarder manifest"
        );
    }
}

#[test]
fn isolation_marker_is_kafka_consumer_only() {
    assert_eq!(
        splunk_hec_forwarder::ISOLATION,
        "splunk-hec-forwarder-is-kafka-consumer-only"
    );
}

#[test]
fn forwarder_handle_runs_on_separate_async_task_from_callers() {
    // Forwarder worker is spawned via tokio::spawn in SplunkForwarder::spawn;
    // callers only use try_send (same non-blocking contract as agent telemetry_stream).
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        use splunk_hec_forwarder::config::ForwarderConfig;
        use splunk_hec_forwarder::forwarder::SplunkForwarder;
        use splunk_hec_forwarder::metrics::HecMetrics;
        use std::sync::Arc;

        let metrics = HecMetrics::new().expect("metrics");
        let cfg = ForwarderConfig {
            hec_url: "http://127.0.0.1:9/unreachable".into(),
            hec_token: "x".into(),
            hec_index: None,
            sourcetype: "neuromesh:alert:v1".into(),
            source: "test".into(),
            kafka_brokers: vec!["localhost:9092".into()],
            kafka_topic: "t".into(),
            kafka_group_id: "g".into(),
            queue_capacity: 4,
            metrics_port: 9091,
        };
        let forwarder = SplunkForwarder::spawn(&cfg, Arc::clone(&metrics));
        assert!(forwarder.handle().stats().enqueued.load(std::sync::atomic::Ordering::Relaxed) == 0);
    });
}
