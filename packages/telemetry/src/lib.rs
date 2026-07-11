//! Standard telemetry contract for Neuromesh observability pipelines.
//!
//! `MetricEvent` is the single source of truth for metrics flowing from Ring 0
//! sensors, user-space orchestrators, and AI inference engines toward Kafka and
//! downstream SIEM/GNN consumers.

use serde::{Deserialize, Serialize};

/// Canonical metric envelope for all Neuromesh telemetry producers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricEvent {
    /// Unique identifier for idempotent Kafka ingestion and deduplication.
    pub event_id: String,
    /// Nanosecond-resolution timestamp (UTC epoch).
    pub timestamp_ns: i64,
    /// Originating node (hostname, Kubernetes node, or agent ID).
    pub node_name: String,
    /// Producer subsystem that emitted this metric.
    pub source: MetricSource,
    /// High-level event classification.
    pub kind: MetricKind,
    /// Cross-cutting dimensions for correlation and filtering.
    pub labels: MetricLabels,
    /// Type-specific payload body.
    pub payload: MetricPayload,
}

/// Telemetry producer identity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MetricSource {
    EbpfLsm,
    EbpfTracepoint,
    Orchestrator,
    AiEngine,
}

/// Metric classification aligned with the Dual-Path architecture.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MetricKind {
    LsmBlock,
    TracepointHit,
    BehavioralAlert,
    AiInference,
    Health,
}

/// Shared labels for process lineage and rule correlation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MetricLabels {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub comm: Option<String>,
    pub binary_path: Option<String>,
    pub rule_id: Option<String>,
    pub severity: Option<String>,
}

/// Discriminated payload variants for Kafka topic routing and GNN feature extraction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MetricPayload {
    LsmBlock {
        denied_path: String,
        matched_pattern: String,
    },
    TracepointHit {
        binary_path: String,
    },
    BehavioralAlert {
        spawn_count: usize,
        window_secs: u64,
    },
    AiInference {
        model_id: String,
        score: f64,
        classification: String,
    },
    Health {
        events_processed: u64,
        lost_events_count: u64,
    },
}

impl MetricEvent {
    pub fn lsm_block(
        event_id: impl Into<String>,
        timestamp_ns: i64,
        node_name: impl Into<String>,
        labels: MetricLabels,
        denied_path: impl Into<String>,
        matched_pattern: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            timestamp_ns,
            node_name: node_name.into(),
            source: MetricSource::EbpfLsm,
            kind: MetricKind::LsmBlock,
            labels,
            payload: MetricPayload::LsmBlock {
                denied_path: denied_path.into(),
                matched_pattern: matched_pattern.into(),
            },
        }
    }

    pub fn tracepoint_hit(
        event_id: impl Into<String>,
        timestamp_ns: i64,
        node_name: impl Into<String>,
        labels: MetricLabels,
        binary_path: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            timestamp_ns,
            node_name: node_name.into(),
            source: MetricSource::EbpfTracepoint,
            kind: MetricKind::TracepointHit,
            labels,
            payload: MetricPayload::TracepointHit {
                binary_path: binary_path.into(),
            },
        }
    }

    pub fn ai_inference(
        event_id: impl Into<String>,
        timestamp_ns: i64,
        node_name: impl Into<String>,
        model_id: impl Into<String>,
        score: f64,
        classification: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            timestamp_ns,
            node_name: node_name.into(),
            source: MetricSource::AiEngine,
            kind: MetricKind::AiInference,
            labels: MetricLabels::default(),
            payload: MetricPayload::AiInference {
                model_id: model_id.into(),
                score,
                classification: classification.into(),
            },
        }
    }

    /// Serialize to a compact JSON line for Kafka producers and log shippers.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_lsm_block_for_kafka() {
        let event = MetricEvent::lsm_block(
            "evt-001",
            1_700_000_000_000_000_000,
            "node-a",
            MetricLabels {
                pid: Some(4242),
                ppid: Some(1),
                comm: Some("bash".to_string()),
                severity: Some("CRITICAL_ALERT".to_string()),
                ..MetricLabels::default()
            },
            "/tmp/evil.bin",
            "/tmp/",
        );

        let json = event.to_json_line().expect("json serialization");
        assert!(json.contains("\"kind\":\"LSM_BLOCK\""));
        assert!(json.contains("\"denied_path\":\"/tmp/evil.bin\""));
    }

    #[test]
    fn serializes_ai_inference_payload() {
        let event = MetricEvent::ai_inference(
            "evt-ai-42",
            1_700_000_000_000_000_001,
            "node-b",
            "gnn-lateral-v1",
            0.97,
            "lateral_movement",
        );

        let json = event.to_json_line().expect("json serialization");
        assert!(json.contains("\"kind\":\"AI_INFERENCE\""));
        assert!(json.contains("\"classification\":\"lateral_movement\""));
    }
}
