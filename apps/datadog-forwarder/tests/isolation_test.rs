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
        "splunk-hec-forwarder",
    ];
    for needle in forbidden {
        assert!(
            !text.contains(needle),
            "forbidden dependency/reference {needle:?} in datadog-forwarder manifest"
        );
    }
}

#[test]
fn isolation_marker_is_kafka_consumer_only() {
    assert_eq!(
        datadog_forwarder::ISOLATION,
        "datadog-forwarder-is-kafka-consumer-only"
    );
}

#[test]
fn source_never_reads_shared_kafka_group_env() {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in fs::read_dir(&src_dir).expect("src dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read rust");
        assert!(
            !text.contains("std::env::var(\"NEUROMESH_KAFKA_GROUP_ID\")"),
            "{} must not read the shared NEUROMESH_KAFKA_GROUP_ID env",
            path.display()
        );
    }
}

#[test]
fn forwarder_handle_runs_on_separate_async_task_from_callers() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        use datadog_forwarder::config::ForwarderConfig;
        use datadog_forwarder::forwarder::DatadogForwarder;
        use datadog_forwarder::metrics::DdMetrics;
        use std::sync::Arc;

        let metrics = DdMetrics::new().expect("metrics");
        let cfg = ForwarderConfig {
            logs_url: "http://127.0.0.1:9/unreachable".into(),
            api_key: "x".into(),
            service: "test".into(),
            ddsource: "neuromesh".into(),
            kafka_brokers: vec!["localhost:9092".into()],
            kafka_topic: "t".into(),
            kafka_group_id: "datadog-forwarder".into(),
            queue_capacity: 4,
            metrics_port: 9092,
        };
        let forwarder = DatadogForwarder::spawn(&cfg, Arc::clone(&metrics));
        assert!(
            forwarder
                .handle()
                .stats()
                .enqueued
                .load(std::sync::atomic::Ordering::Relaxed)
                == 0
        );
    });
}
