//! Kafka telemetry envelope parser (matches `agent-ebpf-sensor` Slow Path export).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

pub const SCHEMA_VERSION: &str = "neuromesh.telemetry.v1";
pub const BEHAVIOR_ALERT: &str = "BEHAVIOR_ALERT";
pub const CRITICAL_ALERT: &str = "CRITICAL_ALERT";

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TelemetryEnvelope {
    pub event_id: String,
    pub timestamp_ns: i64,
    pub node_name: String,
    pub schema_version: String,
    pub alert_type: String,
    pub payload: Value,
}

impl TelemetryEnvelope {
    pub fn parse_json(raw: &[u8]) -> Result<Self> {
        let env: Self = serde_json::from_slice(raw).context("invalid telemetry JSON")?;
        env.validate()?;
        Ok(env)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "unsupported schema_version: {} (want {SCHEMA_VERSION})",
                self.schema_version
            );
        }
        if self.alert_type != BEHAVIOR_ALERT && self.alert_type != CRITICAL_ALERT {
            bail!("unsupported alert_type: {}", self.alert_type);
        }
        Ok(())
    }

    pub fn rule_id(&self) -> Option<&str> {
        self.payload.get("rule_id").and_then(|v| v.as_str())
    }

    pub fn severity(&self) -> Option<&str> {
        self.payload
            .get("severity")
            .and_then(|v| v.as_str())
            .or(Some(self.alert_type.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_critical_envelope() {
        let raw = br#"{
            "event_id": "evt-1",
            "timestamp_ns": 1710000000000000000,
            "node_name": "worker-01",
            "schema_version": "neuromesh.telemetry.v1",
            "alert_type": "CRITICAL_ALERT",
            "payload": {
                "rule_id": "NEUROMESH-EXEC-BLACKLIST-PATH",
                "severity": "CRITICAL_ALERT",
                "binary_path": "/tmp/evil.bin"
            }
        }"#;
        let env = TelemetryEnvelope::parse_json(raw).expect("parse");
        assert_eq!(env.event_id, "evt-1");
        assert_eq!(env.rule_id(), Some("NEUROMESH-EXEC-BLACKLIST-PATH"));
    }
}
