//! Splunk HEC payload mapping and HTTP client.

use crate::envelope::TelemetryEnvelope;
use anyhow::{Context, Result};
use reqwest::StatusCode;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HecEventBody {
    pub time: f64,
    pub host: String,
    pub source: String,
    pub sourcetype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    pub event: HecEventPayload,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HecEventPayload {
    pub event_id: String,
    pub schema_version: String,
    pub alert_type: String,
    pub payload: serde_json::Value,
    pub rule_id: Option<String>,
    pub severity: Option<String>,
    pub meta: HecEventMeta,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HecEventMeta {
    pub producer: String,
    pub transport: String,
}

pub fn build_hec_event(
    envelope: &TelemetryEnvelope,
    source: &str,
    sourcetype: &str,
    index: Option<&str>,
) -> HecEventBody {
    HecEventBody {
        time: envelope.timestamp_ns as f64 / 1_000_000_000.0,
        host: envelope.node_name.clone(),
        source: source.to_string(),
        sourcetype: sourcetype.to_string(),
        index: index.map(str::to_string),
        event: HecEventPayload {
            event_id: envelope.event_id.clone(),
            schema_version: envelope.schema_version.clone(),
            alert_type: envelope.alert_type.clone(),
            payload: envelope.payload.clone(),
            rule_id: envelope.rule_id().map(str::to_string),
            severity: envelope.severity().map(str::to_string),
            meta: HecEventMeta {
                producer: "agent-ebpf-sensor".to_string(),
                transport: "kafka->hec".to_string(),
            },
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HecSendOutcome {
    Success,
    RetryableFailure,
    NonRetryableFailure,
}

pub struct SplunkHecClient {
    http: reqwest::Client,
    url: String,
    token: String,
}

impl SplunkHecClient {
    pub fn new(url: impl Into<String>, token: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client");
        Self {
            http,
            url: url.into(),
            token: token.into(),
        }
    }

    pub async fn send(&self, body: &HecEventBody) -> Result<HecSendOutcome> {
        let response = self
            .http
            .post(&self.url)
            .header("Authorization", format!("Splunk {}", self.token))
            .json(body)
            .send()
            .await
            .context("hec http send")?;

        let status = response.status();
        if status.is_success() {
            return Ok(HecSendOutcome::Success);
        }
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Ok(HecSendOutcome::RetryableFailure);
        }
        Ok(HecSendOutcome::NonRetryableFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::TelemetryEnvelope;
    use serde_json::json;

    fn sample_envelope() -> TelemetryEnvelope {
        TelemetryEnvelope {
            event_id: "NEUROMESH-EXEC-SPAWN-BURST-4242-110".into(),
            timestamp_ns: 1_710_000_000_000_000_000,
            node_name: "node-b".into(),
            schema_version: crate::envelope::SCHEMA_VERSION.into(),
            alert_type: crate::envelope::BEHAVIOR_ALERT.into(),
            payload: json!({
                "timestamp": "2026-07-12T10:00:01Z",
                "severity": "BEHAVIOR_ALERT",
                "rule_id": "NEUROMESH-EXEC-SPAWN-BURST",
                "spawn_count": 8
            }),
        }
    }

    #[test]
    fn maps_envelope_to_hec_shape() {
        let hec = build_hec_event(
            &sample_envelope(),
            "neuromesh/agent-ebpf-sensor",
            "neuromesh:alert:v1",
            None,
        );
        assert_eq!(hec.host, "node-b");
        assert_eq!(hec.sourcetype, "neuromesh:alert:v1");
        assert!((hec.time - 1_710_000_000.0).abs() < 0.001);
        assert_eq!(hec.event.event_id, "NEUROMESH-EXEC-SPAWN-BURST-4242-110");
        assert_eq!(
            hec.event.rule_id.as_deref(),
            Some("NEUROMESH-EXEC-SPAWN-BURST")
        );
        assert_eq!(hec.event.meta.transport, "kafka->hec");

        let serialized = serde_json::to_value(&hec).expect("json");
        assert!(serialized.get("event").is_some());
        assert!(serialized.get("time").is_some());
        assert!(serialized.get("sourcetype").is_some());
    }
}
