//! Environment-driven configuration — default-off until URL + token file are set.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub const SPLUNK_HEC_URL_ENV: &str = "NEUROMESH_SPLUNK_HEC_URL";
pub const SPLUNK_HEC_TOKEN_FILE_ENV: &str = "NEUROMESH_SPLUNK_HEC_TOKEN_FILE";
pub const SPLUNK_HEC_INDEX_ENV: &str = "NEUROMESH_SPLUNK_HEC_INDEX";
pub const SPLUNK_HEC_SOURCETYPE_ENV: &str = "NEUROMESH_SPLUNK_HEC_SOURCETYPE";
pub const SPLUNK_HEC_SOURCE_ENV: &str = "NEUROMESH_SPLUNK_HEC_SOURCE";

pub const KAFKA_BROKERS_ENV: &str = "NEUROMESH_KAFKA_BROKERS";
pub const KAFKA_TOPIC_ENV: &str = "NEUROMESH_KAFKA_TOPIC";
pub const KAFKA_GROUP_ID_ENV: &str = "NEUROMESH_KAFKA_GROUP_ID";

pub const DEFAULT_KAFKA_TOPIC: &str = "neuromesh.telemetry.v1";
pub const DEFAULT_KAFKA_GROUP: &str = "splunk-hec-forwarder";
pub const DEFAULT_SOURCETYPE: &str = "neuromesh:alert:v1";
pub const DEFAULT_SOURCE: &str = "neuromesh/agent-ebpf-sensor";
pub const DEFAULT_QUEUE_CAPACITY: usize = 8192;
pub const DEFAULT_METRICS_PORT: u16 = 9091;

pub const QUEUE_CAPACITY_ENV: &str = "NEUROMESH_SPLUNK_HEC_QUEUE_CAPACITY";
pub const METRICS_PORT_ENV: &str = "NEUROMESH_SPLUNK_HEC_METRICS_PORT";

#[derive(Debug, Clone)]
pub struct ForwarderConfig {
    pub hec_url: String,
    pub hec_token: String,
    pub hec_index: Option<String>,
    pub sourcetype: String,
    pub source: String,
    pub kafka_brokers: Vec<String>,
    pub kafka_topic: String,
    pub kafka_group_id: String,
    pub queue_capacity: usize,
    pub metrics_port: u16,
}

impl ForwarderConfig {
    /// Returns `None` when Splunk HEC forwarding is not fully configured (default-off).
    pub fn from_env() -> Option<Self> {
        let hec_url = std::env::var(SPLUNK_HEC_URL_ENV)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())?;

        let token = load_hec_token_file().ok()?;

        let kafka_brokers = std::env::var(KAFKA_BROKERS_ENV)
            .ok()?
            .split(',')
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if kafka_brokers.is_empty() {
            return None;
        }

        Some(Self {
            hec_url,
            hec_token: token,
            hec_index: std::env::var(SPLUNK_HEC_INDEX_ENV)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            sourcetype: std::env::var(SPLUNK_HEC_SOURCETYPE_ENV)
                .unwrap_or_else(|_| DEFAULT_SOURCETYPE.to_string()),
            source: std::env::var(SPLUNK_HEC_SOURCE_ENV)
                .unwrap_or_else(|_| DEFAULT_SOURCE.to_string()),
            kafka_brokers,
            kafka_topic: std::env::var(KAFKA_TOPIC_ENV)
                .unwrap_or_else(|_| DEFAULT_KAFKA_TOPIC.to_string()),
            kafka_group_id: std::env::var(KAFKA_GROUP_ID_ENV)
                .unwrap_or_else(|_| DEFAULT_KAFKA_GROUP.to_string()),
            queue_capacity: std::env::var(QUEUE_CAPACITY_ENV)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_QUEUE_CAPACITY),
            metrics_port: std::env::var(METRICS_PORT_ENV)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_METRICS_PORT),
        })
    }

    /// Strict loader for tests and explicit startup validation.
    pub fn load_hec_token_from_env() -> Result<String> {
        load_hec_token_file()
    }
}

fn load_hec_token_file() -> Result<String> {
    let path = std::env::var(SPLUNK_HEC_TOKEN_FILE_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("{SPLUNK_HEC_TOKEN_FILE_ENV} not set — Splunk HEC inactive")
        })?;

    let pb = PathBuf::from(&path);
    if !pb.is_absolute() {
        bail!("{SPLUNK_HEC_TOKEN_FILE_ENV} must be an absolute path, got {path:?}");
    }

    let raw = std::fs::read_to_string(&pb)
        .with_context(|| format!("read {SPLUNK_HEC_TOKEN_FILE_ENV} at {}", pb.display()))?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        bail!(
            "{SPLUNK_HEC_TOKEN_FILE_ENV} ({}) is empty",
            pb.display()
        );
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_token(path: &std::path::Path, token: &str) {
        let mut f = std::fs::File::create(path).expect("create token file");
        f.write_all(token.as_bytes()).expect("write token");
    }

    #[test]
    fn missing_token_file_yields_inactive_not_panic() {
        let dir = std::env::temp_dir().join(format!(
            "nm-hec-token-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");

        let missing = dir.join("missing-token");
        std::env::set_var(SPLUNK_HEC_TOKEN_FILE_ENV, missing.to_string_lossy().to_string());
        assert!(ForwarderConfig::load_hec_token_from_env().is_err());
        assert!(ForwarderConfig::from_env().is_none());

        std::env::remove_var(SPLUNK_HEC_TOKEN_FILE_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_env_none_without_url_or_kafka() {
        std::env::remove_var(SPLUNK_HEC_URL_ENV);
        std::env::remove_var(SPLUNK_HEC_TOKEN_FILE_ENV);
        std::env::remove_var(KAFKA_BROKERS_ENV);
        assert!(ForwarderConfig::from_env().is_none());
    }

    #[test]
    fn from_env_active_when_url_token_kafka_present() {
        let dir = std::env::temp_dir().join(format!("nm-hec-token-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let token_path = dir.join("hec.token");
        write_token(&token_path, "test-hec-token\n");

        std::env::set_var(SPLUNK_HEC_URL_ENV, "http://127.0.0.1:8088/services/collector/event");
        std::env::set_var(SPLUNK_HEC_TOKEN_FILE_ENV, token_path.to_string_lossy().to_string());
        std::env::set_var(KAFKA_BROKERS_ENV, "localhost:9092");

        let cfg = ForwarderConfig::from_env().expect("configured");
        assert_eq!(cfg.hec_token, "test-hec-token");
        assert_eq!(cfg.kafka_topic, DEFAULT_KAFKA_TOPIC);

        std::env::remove_var(SPLUNK_HEC_URL_ENV);
        std::env::remove_var(SPLUNK_HEC_TOKEN_FILE_ENV);
        std::env::remove_var(KAFKA_BROKERS_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
