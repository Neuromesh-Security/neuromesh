use agent_ebpf_sensor::normalizer::{DataNormalizer, SEVERITY_BEHAVIOR_ALERT};
use neuromesh_integration_tests::fixtures::{benign_events, malicious_spawn_burst_events};
use std::time::Duration;

#[test]
fn benign_low_frequency_spawns_do_not_trigger_behavior_alert() {
    let mut normalizer = DataNormalizer::with_config(Duration::from_secs(2), 8, 64);

    for event in benign_events() {
        assert!(
            normalizer.ingest(&event).is_none(),
            "benign traffic should not emit BEHAVIOR_ALERT"
        );
    }
}

#[test]
fn rapid_spawn_burst_triggers_behavior_alert() {
    let mut normalizer = DataNormalizer::with_config(Duration::from_secs(2), 8, 64);
    let mut alert = None;

    for event in malicious_spawn_burst_events() {
        alert = normalizer.ingest(&event);
    }

    let alert = alert.expect("expected BEHAVIOR_ALERT after burst threshold");
    assert_eq!(alert.severity, SEVERITY_BEHAVIOR_ALERT);
    assert_eq!(alert.rule_id, "NEUROMESH-EXEC-SPAWN-BURST");
    assert_eq!(alert.ppid, 4242);
    assert!(alert.spawn_count >= 8);
    assert_eq!(alert.last_comm, "bash");
}

#[test]
fn zero_ppid_events_are_ignored_for_burst_detection() {
    let mut normalizer = DataNormalizer::with_config(Duration::from_secs(2), 3, 16);
    let events = malicious_spawn_burst_events()
        .into_iter()
        .map(|mut event| {
            event.ppid = 0;
            event
        })
        .collect::<Vec<_>>();

    for event in events {
        assert!(normalizer.ingest(&event).is_none());
    }
}
