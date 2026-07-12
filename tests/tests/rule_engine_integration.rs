use agent_ebpf_sensor::rules::{RuleEngine, RuleVerdict, SEVERITY_CRITICAL_ALERT};
use neuromesh_integration_tests::fixtures::{
    benign_events, malicious_blacklist_events, telemetry_event,
};

#[test]
fn benign_paths_are_suppressed() {
    let engine = RuleEngine::new();

    for event in benign_events() {
        assert_eq!(
            engine.evaluate(&event),
            RuleVerdict::Suppressed,
            "expected benign path to be suppressed"
        );
    }
}

#[test]
fn blacklisted_tmp_path_triggers_critical_alert() {
    let engine = RuleEngine::new();
    let event = telemetry_event(9001, 1, "/tmp/evil.bin", "bash", 1000);

    let verdict = engine.evaluate(&event);
    assert!(matches!(verdict, RuleVerdict::Alert(_)));

    if let RuleVerdict::Alert(alert) = verdict {
        assert_eq!(alert.severity, SEVERITY_CRITICAL_ALERT);
        assert_eq!(alert.rule_id, "NEUROMESH-EXEC-BLACKLIST-PATH");
        assert_eq!(alert.matched_pattern, "/tmp/");
        assert_eq!(alert.binary_path, "/tmp/evil.bin");
        assert_eq!(alert.ppid, 1);
    }
}

#[test]
fn all_malicious_staging_prefixes_are_flagged() {
    let engine = RuleEngine::new();

    for event in malicious_blacklist_events() {
        assert!(
            matches!(engine.evaluate(&event), RuleVerdict::Alert(_)),
            "expected blacklist alert for staging path"
        );
    }
}

#[test]
fn lotl_bash_from_legitimate_path_is_not_blacklisted() {
    let engine = RuleEngine::new();
    let event = telemetry_event(9100, 99, "/usr/bin/bash", "bash", 1000);

    assert_eq!(engine.evaluate(&event), RuleVerdict::Suppressed);
}
