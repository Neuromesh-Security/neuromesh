use neuromesh_common::{SecurityTelemetryEvent, MAX_COMM_LEN};
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Severity for behavioral detections that bypass static path rules.
pub const SEVERITY_BEHAVIOR_ALERT: &str = "BEHAVIOR_ALERT";

/// Sliding-window burst detector.
///
/// Primary key is parent process ID (`ppid`). When kernel lineage capture fails
/// (`ppid_unresolved`), events are still counted under a **comm** fallback key
/// so real spawn bursts remain visible; alerts are tagged `ppid_unresolved`.
/// Genuine `ppid == 0` without that flag (orphan / init edge) stays ignored to
/// avoid correlating unrelated processes into a shared `0` bucket.
#[derive(Debug)]
pub struct DataNormalizer {
    window: Duration,
    burst_threshold: usize,
    parent_spawns: HashMap<u32, Vec<Instant>>,
    /// Fallback buckets when `ppid` could not be resolved (keyed by child `comm`).
    unresolved_comm_spawns: HashMap<[u8; MAX_COMM_LEN], Vec<Instant>>,
    batch: Vec<SecurityTelemetryEvent>,
    batch_limit: usize,
}

/// JSON alert emitted when spawn frequency exceeds the configured threshold.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BehaviorAlert {
    pub timestamp: String,
    pub severity: String,
    pub rule_id: String,
    pub rule_name: String,
    pub ppid: u32,
    /// True when the burst was correlated by `comm` because parent lineage
    /// capture failed (`CAPTURE_PPID`). `ppid` is then `0` and must not be
    /// treated as a real parent id.
    pub ppid_unresolved: bool,
    pub spawn_count: usize,
    pub window_secs: u64,
    pub last_pid: u32,
    pub last_comm: String,
    pub last_binary_path: String,
}

impl DataNormalizer {
    pub fn new() -> Self {
        Self::with_config(Duration::from_secs(2), 8, 64)
    }

    /// Deterministic configuration for integration and property tests.
    pub fn with_config(window: Duration, burst_threshold: usize, batch_limit: usize) -> Self {
        Self {
            window,
            burst_threshold,
            parent_spawns: HashMap::new(),
            unresolved_comm_spawns: HashMap::new(),
            batch: Vec::with_capacity(batch_limit),
            batch_limit,
        }
    }

    /// Queue an event for batch processing and return any behavioral alert.
    pub fn ingest(&mut self, event: &SecurityTelemetryEvent) -> Option<BehaviorAlert> {
        self.batch.push(*event);
        if self.batch.len() >= self.batch_limit {
            return self.flush();
        }
        self.analyze_parent_frequency(event)
    }

    /// Drain the pending batch and evaluate the most recent event for bursts.
    pub fn flush(&mut self) -> Option<BehaviorAlert> {
        let last = self.batch.last().copied();
        self.batch.clear();
        last.and_then(|event| self.analyze_parent_frequency(&event))
    }

    fn analyze_parent_frequency(
        &mut self,
        event: &SecurityTelemetryEvent,
    ) -> Option<BehaviorAlert> {
        let now = Instant::now();
        let window = self.window;
        let threshold = self.burst_threshold;

        let (spawn_count, ppid_unresolved) = if event.ppid_unresolved {
            let entries = self.unresolved_comm_spawns.entry(event.comm).or_default();
            entries.retain(|timestamp| now.duration_since(*timestamp) < window);
            entries.push(now);
            (entries.len(), true)
        } else if event.ppid == 0 {
            // Genuine unresolved orphan / init edge — do not share a `0` bucket.
            return None;
        } else {
            let entries = self.parent_spawns.entry(event.ppid).or_default();
            entries.retain(|timestamp| now.duration_since(*timestamp) < window);
            entries.push(now);
            (entries.len(), false)
        };

        if spawn_count < threshold {
            return None;
        }

        let rule_name = if ppid_unresolved {
            "Abnormal process execution burst (ppid unresolved; correlated by comm)"
        } else {
            "Abnormal process execution burst from single parent"
        };

        Some(BehaviorAlert {
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: SEVERITY_BEHAVIOR_ALERT.to_string(),
            rule_id: "NEUROMESH-EXEC-SPAWN-BURST".to_string(),
            rule_name: rule_name.to_string(),
            ppid: if ppid_unresolved { 0 } else { event.ppid },
            ppid_unresolved,
            spawn_count,
            window_secs: self.window.as_secs(),
            last_pid: event.pid,
            last_comm: extract_comm(event),
            last_binary_path: extract_filename(event),
        })
    }
}

impl Default for DataNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_filename(event: &SecurityTelemetryEvent) -> String {
    match std::ffi::CStr::from_bytes_until_nul(&event.filename) {
        Ok(cstr) => cstr.to_string_lossy().into_owned(),
        Err(_) => "[Invalid Path]".to_string(),
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
    use neuromesh_common::MAX_FILENAME_LEN;

    fn lineage_event(
        ppid: u32,
        pid: u32,
        path: &str,
        comm: &str,
        ppid_unresolved: bool,
    ) -> SecurityTelemetryEvent {
        let mut filename = [0u8; MAX_FILENAME_LEN];
        filename[..path.len()].copy_from_slice(path.as_bytes());
        let mut comm_buf = [0u8; MAX_COMM_LEN];
        comm_buf[..comm.len()].copy_from_slice(comm.as_bytes());
        SecurityTelemetryEvent {
            pid,
            ppid,
            ppid_unresolved,
            uid: 1000,
            euid: 1000,
            comm: comm_buf,
            filename,
            argv_len: 0,
            argv_truncated: false,
            argv_trunc_mask: 0,
            argv: [0; neuromesh_common::MAX_ARGV_LEN],
        }
    }

    #[test]
    fn detects_spawn_burst_from_single_parent() {
        let mut normalizer = DataNormalizer::new();
        let mut alert = None;

        for pid in 100..108 {
            alert = normalizer.ingest(&lineage_event(42, pid, "/usr/bin/true", "bash", false));
        }

        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.ppid, 42);
        assert!(!alert.ppid_unresolved);
        assert_eq!(alert.severity, SEVERITY_BEHAVIOR_ALERT);
    }

    /// Genuine `ppid == 0` without a capture fault must stay ignored (no shared
    /// orphan bucket), matching the historical FP-suppression contract.
    #[test]
    fn genuine_zero_ppid_without_unresolved_flag_is_ignored() {
        let mut normalizer = DataNormalizer::with_config(Duration::from_secs(2), 3, 16);
        for pid in 100..110 {
            assert!(normalizer
                .ingest(&lineage_event(0, pid, "/usr/bin/true", "bash", false))
                .is_none());
        }
    }

    /// When lineage capture fails, bursts must still surface — keyed by `comm`,
    /// with `ppid_unresolved` set so analysts do not treat `ppid=0` as parent 0.
    #[test]
    fn ppid_unresolved_burst_is_detected_via_comm_fallback() {
        let mut normalizer = DataNormalizer::with_config(Duration::from_secs(2), 3, 16);
        let mut alert = None;
        for pid in 100..103 {
            alert = normalizer.ingest(&lineage_event(0, pid, "/usr/bin/curl", "curl", true));
        }
        let alert = alert.expect("unresolved-ppid burst must still alert");
        assert!(alert.ppid_unresolved);
        assert_eq!(alert.ppid, 0);
        assert_eq!(alert.last_comm, "curl");
        assert!(alert.rule_name.contains("ppid unresolved"));
        assert!(alert.spawn_count >= 3);
    }

    /// Different `comm` values must not share an unresolved fallback bucket.
    #[test]
    fn unresolved_fallback_does_not_cross_correlate_distinct_comms() {
        let mut normalizer = DataNormalizer::with_config(Duration::from_secs(2), 3, 16);
        for pid in 100..102 {
            assert!(normalizer
                .ingest(&lineage_event(0, pid, "/usr/bin/curl", "curl", true))
                .is_none());
        }
        for pid in 200..202 {
            assert!(normalizer
                .ingest(&lineage_event(0, pid, "/usr/bin/wget", "wget", true))
                .is_none());
        }
    }
}
