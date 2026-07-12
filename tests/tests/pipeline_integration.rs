use agent_ebpf_sensor::mocks::MockRingBuf;
use agent_ebpf_sensor::mocks::TelemetrySource;
use agent_ebpf_sensor::pipeline::TelemetryPipeline;
use agent_ebpf_sensor::rules::SEVERITY_CRITICAL_ALERT;
use neuromesh_integration_tests::fixtures::mixed_ringbuf_drain;

#[test]
fn mock_ringbuf_feeds_pipeline_without_kernel() {
    let mut ring = MockRingBuf::from_events(mixed_ringbuf_drain());
    let mut pipeline = TelemetryPipeline::new();

    let drained = ring.drain();
    assert!(!drained.is_empty());

    let output = pipeline.process_batch(&drained);

    assert!(
        !output.siem_alerts.is_empty(),
        "malicious staging paths should produce SIEM alerts"
    );
    assert!(
        !output.behavior_alerts.is_empty(),
        "spawn burst should produce BEHAVIOR_ALERT"
    );

    assert!(
        output
            .siem_alerts
            .iter()
            .any(|alert| alert.severity == SEVERITY_CRITICAL_ALERT),
        "expected CRITICAL_ALERT from blacklist matches"
    );

    assert_eq!(ring.pending_count(), 0);
    assert!(ring.health_stats().events_processed > 0);
}

#[test]
fn static_telemetry_source_drives_pipeline() {
    use agent_ebpf_sensor::mocks::StaticTelemetrySource;
    use neuromesh_integration_tests::fixtures::malicious_blacklist_events;

    let mut source = StaticTelemetrySource::new(vec![malicious_blacklist_events()]);
    let drained = source.drain_events();
    let mut pipeline = TelemetryPipeline::new();
    let output = pipeline.process_batch(&drained);

    assert_eq!(output.siem_alerts.len(), 3);
    assert!(output.behavior_alerts.is_empty());
    assert_eq!(source.health_stats().events_processed, 3);
}
