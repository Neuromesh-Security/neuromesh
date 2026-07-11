use neuromesh_common::SecurityTelemetryEvent;
use serde::Serialize;
use std::borrow::Cow;

/// Severity emitted for blacklist / threat-signature matches.
pub const SEVERITY_CRITICAL_ALERT: &str = "CRITICAL_ALERT";

/// Exact binary paths silently dropped to reduce operational noise.
const WHITELIST_PATHS: &[&str] = &["/bin/ls", "/bin/cat", "/usr/bin/git", "/usr/bin/bash"];

/// Directory prefixes associated with malware staging and rootkit drop zones.
const BLACKLIST_PREFIXES: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

/// Outcome of applying detection rules to a single telemetry event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleVerdict {
    /// Benign system activity — discard without emission.
    Suppressed,
    /// Actionable detection — serialize to JSON for downstream SIEM ingestion.
    Alert(SiemAlert),
}

/// Structured alert payload mapped to JSON for Elasticsearch/Datadog pipelines.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SiemAlert {
    pub timestamp: String,
    pub severity: String,
    pub rule_id: String,
    pub rule_name: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub euid: u32,
    pub comm: String,
    pub binary_path: String,
    pub matched_pattern: String,
}

/// User-space detection brain: whitelist noise reduction + blacklist threat signatures.
#[derive(Debug, Clone)]
pub struct RuleEngine;

impl RuleEngine {
    pub fn new() -> Self {
        Self
    }

    /// Classify a kernel telemetry event against whitelist and blacklist policies.
    pub fn evaluate(&self, event: &SecurityTelemetryEvent) -> RuleVerdict {
        let path = extract_filename(event);

        if Self::is_whitelisted(&path) {
            return RuleVerdict::Suppressed;
        }

        if let Some(prefix) = Self::blacklist_match(&path) {
            return RuleVerdict::Alert(SiemAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                severity: SEVERITY_CRITICAL_ALERT.to_string(),
                rule_id: "NEUROMESH-EXEC-BLACKLIST-PATH".to_string(),
                rule_name: "Execution from ephemeral malware staging directory".to_string(),
                pid: event.pid,
                ppid: event.ppid,
                uid: event.uid,
                euid: event.euid,
                comm: extract_comm(event),
                binary_path: path.into_owned(),
                matched_pattern: prefix.to_string(),
            });
        }

        RuleVerdict::Suppressed
    }

    /// Serialize an alert to a compact, strictly valid JSON line for SIEM forwarding.
    pub fn format_json(alert: &SiemAlert) -> Result<String, serde_json::Error> {
        serde_json::to_string(alert)
    }

    fn is_whitelisted(path: &str) -> bool {
        WHITELIST_PATHS.contains(&path)
    }

    fn blacklist_match(path: &str) -> Option<&'static str> {
        BLACKLIST_PREFIXES
            .iter()
            .copied()
            .find(|prefix| path.starts_with(prefix))
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_filename(event: &SecurityTelemetryEvent) -> Cow<'_, str> {
    match std::ffi::CStr::from_bytes_until_nul(&event.filename) {
        Ok(cstr) => cstr.to_string_lossy(),
        Err(_) => Cow::Borrowed("[Invalid Path]"),
    }
}

fn extract_comm(event: &SecurityTelemetryEvent) -> String {
    match std::ffi::CStr::from_bytes_until_nul(&event.comm) {
        Ok(cstr) => cstr.to_string_lossy().into_owned(),
        Err(_) => "[Unknown]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neuromesh_common::{MAX_COMM_LEN, MAX_FILENAME_LEN};

    fn event_with_path(path: &str) -> SecurityTelemetryEvent {
        let mut filename = [0u8; MAX_FILENAME_LEN];
        let bytes = path.as_bytes();
        filename[..bytes.len()].copy_from_slice(bytes);
        SecurityTelemetryEvent {
            pid: 4242,
            ppid: 1,
            uid: 1000,
            euid: 1000,
            comm: [0u8; MAX_COMM_LEN],
            filename,
        }
    }

    #[test]
    fn whitelist_suppresses_benign_binaries() {
        let engine = RuleEngine::new();
        for path in ["/bin/ls", "/bin/cat", "/usr/bin/git", "/usr/bin/bash"] {
            let verdict = engine.evaluate(&event_with_path(path));
            assert_eq!(verdict, RuleVerdict::Suppressed);
        }
    }

    #[test]
    fn blacklist_flags_ephemeral_directories() {
        let engine = RuleEngine::new();
        let verdict = engine.evaluate(&event_with_path("/tmp/evil.bin"));
        assert!(matches!(verdict, RuleVerdict::Alert(_)));
        if let RuleVerdict::Alert(alert) = verdict {
            assert_eq!(alert.severity, SEVERITY_CRITICAL_ALERT);
            assert_eq!(alert.matched_pattern, "/tmp/");
        }
    }
}
