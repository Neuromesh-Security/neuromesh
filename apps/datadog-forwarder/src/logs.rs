//! Datadog Logs API v2 payload mapping and HTTP client.

use crate::envelope::TelemetryEnvelope;
use anyhow::{Context, Result};
use reqwest::StatusCode;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DatadogLogItem {
    pub message: String,
    pub hostname: String,
    pub service: String,
    pub ddsource: String,
    pub ddtags: String,
    pub event_id: String,
    pub schema_version: String,
    pub alert_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub timestamp: f64,
    pub payload: serde_json::Value,
}

pub fn build_datadog_log(
    envelope: &TelemetryEnvelope,
    service: &str,
    ddsource: &str,
) -> DatadogLogItem {
    let rule_id = envelope.rule_id().map(str::to_string);
    let message = match rule_id.as_deref() {
        Some(rule) => format!("{} {} on {}", envelope.alert_type, rule, envelope.node_name),
        None => format!("{} on {}", envelope.alert_type, envelope.node_name),
    };
    let mut tags = vec![
        format!("source:{ddsource}"),
        format!("alert_type:{}", envelope.alert_type),
    ];
    if let Some(rule) = rule_id.as_deref() {
        tags.push(format!("rule_id:{rule}"));
    }

    DatadogLogItem {
        message,
        hostname: envelope.node_name.clone(),
        service: service.to_string(),
        ddsource: ddsource.to_string(),
        ddtags: tags.join(","),
        event_id: envelope.event_id.clone(),
        schema_version: envelope.schema_version.clone(),
        alert_type: envelope.alert_type.clone(),
        rule_id,
        timestamp: envelope.timestamp_ns as f64 / 1_000_000_000.0,
        payload: envelope.payload.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DdSendOutcome {
    Success,
    RetryableFailure,
    NonRetryableFailure,
}

pub struct DatadogLogClient {
    http: reqwest::Client,
    url: String,
    api_key: String,
}

impl DatadogLogClient {
    pub fn new(url: impl Into<String>, api_key: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client");
        Self {
            http,
            url: url.into(),
            api_key: api_key.into(),
        }
    }

    pub async fn send(&self, body: &DatadogLogItem) -> Result<DdSendOutcome> {
        let response = self
            .http
            .post(&self.url)
            .header("DD-API-KEY", &self.api_key)
            .json(body)
            .send()
            .await
            .context("datadog logs http send")?;

        let status = response.status();
        if status.is_success() {
            return Ok(DdSendOutcome::Success);
        }
        if status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
            || status.is_server_error()
        {
            return Ok(DdSendOutcome::RetryableFailure);
        }
        Ok(DdSendOutcome::NonRetryableFailure)
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
    fn maps_envelope_to_datadog_logs_v2_shape() {
        let item = build_datadog_log(
            &sample_envelope(),
            "neuromesh-agent-ebpf-sensor",
            "neuromesh",
        );
        assert_eq!(item.hostname, "node-b");
        assert_eq!(item.service, "neuromesh-agent-ebpf-sensor");
        assert_eq!(item.ddsource, "neuromesh");
        assert!(item.message.contains("BEHAVIOR_ALERT"));
        assert!(item.message.contains("NEUROMESH-EXEC-SPAWN-BURST"));
        assert_eq!(item.rule_id.as_deref(), Some("NEUROMESH-EXEC-SPAWN-BURST"));
        assert!(item.ddtags.contains("alert_type:BEHAVIOR_ALERT"));
        assert!((item.timestamp - 1_710_000_000.0).abs() < 0.001);

        let serialized = serde_json::to_value(&item).expect("json");
        assert!(serialized.get("message").is_some());
        assert!(serialized.get("hostname").is_some());
        assert!(serialized.get("ddsource").is_some());
        assert!(serialized.get("payload").is_some());
    }
}
