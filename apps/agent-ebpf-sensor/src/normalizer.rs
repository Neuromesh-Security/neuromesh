use neuromesh_common::SecurityTelemetryEvent;
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Severity for behavioral detections that bypass static path rules.
pub const SEVERITY_BEHAVIOR_ALERT: &str = "BEHAVIOR_ALERT";

/// Sliding-window burst detector keyed on parent process ID (`ppid`).
///
/// Batches incoming RingBuf events and performs real-time frequency analysis to
/// surface fork bombs and abnormal execution bursts from a single parent.
#[derive(Debug)]
pub struct DataNormalizer {
    window: Duration,
    burst_threshold: usize,
    parent_spawns: HashMap<u32, Vec<Instant>>,
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
        if event.ppid == 0 {
            return None;
        }

        let now = Instant::now();
        let entries = self.parent_spawns.entry(event.ppid).or_default();
        entries.retain(|timestamp| now.duration_since(*timestamp) < self.window);
        entries.push(now);

        if entries.len() < self.burst_threshold {
            return None;
        }

        Some(BehaviorAlert {
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: SEVERITY_BEHAVIOR_ALERT.to_string(),
            rule_id: "NEUROMESH-EXEC-SPAWN-BURST".to_string(),
            rule_name: "Abnormal process execution burst from single parent".to_string(),
            ppid: event.ppid,
            spawn_count: entries.len(),
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
    use neuromesh_common::{MAX_COMM_LEN, MAX_FILENAME_LEN};

    fn lineage_event(ppid: u32, pid: u32, path: &str, comm: &str) -> SecurityTelemetryEvent {
        let mut filename = [0u8; MAX_FILENAME_LEN];
        filename[..path.len()].copy_from_slice(path.as_bytes());
        let mut comm_buf = [0u8; MAX_COMM_LEN];
        comm_buf[..comm.len()].copy_from_slice(comm.as_bytes());
        SecurityTelemetryEvent {
            pid,
            ppid,
            uid: 1000,
            euid: 1000,
            comm: comm_buf,
            filename,
        }
    }

    #[test]
    fn detects_spawn_burst_from_single_parent() {
        let mut normalizer = DataNormalizer::new();
        let mut alert = None;

        for pid in 100..108 {
            alert = normalizer.ingest(&lineage_event(42, pid, "/usr/bin/true", "bash"));
        }

        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.ppid, 42);
        assert_eq!(alert.severity, SEVERITY_BEHAVIOR_ALERT);
    }
}
