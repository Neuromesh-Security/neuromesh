//! Environment-driven configuration — default-off until site/URL + API key file are set.
//!
//! Kafka group identity uses `NEUROMESH_DATADOG_KAFKA_GROUP_ID` (default
//! `datadog-forwarder`). This crate **never** reads `NEUROMESH_KAFKA_GROUP_ID`,
//! which belongs to `ai-threat-detector` (and must stay distinct from
//! `splunk-hec-forwarder`).

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub const DATADOG_SITE_ENV: &str = "NEUROMESH_DATADOG_SITE";
pub const DATADOG_LOGS_URL_ENV: &str = "NEUROMESH_DATADOG_LOGS_URL";
pub const DATADOG_API_KEY_FILE_ENV: &str = "NEUROMESH_DATADOG_API_KEY_FILE";
pub const DATADOG_SERVICE_ENV: &str = "NEUROMESH_DATADOG_SERVICE";
pub const DATADOG_SOURCE_ENV: &str = "NEUROMESH_DATADOG_SOURCE";

pub const KAFKA_BROKERS_ENV: &str = "NEUROMESH_KAFKA_BROKERS";
pub const KAFKA_TOPIC_ENV: &str = "NEUROMESH_DATADOG_KAFKA_TOPIC";
pub const KAFKA_GROUP_ID_ENV: &str = "NEUROMESH_DATADOG_KAFKA_GROUP_ID";

pub const DEFAULT_KAFKA_TOPIC: &str = "neuromesh.telemetry.v1";
pub const DEFAULT_KAFKA_GROUP: &str = "datadog-forwarder";
pub const DEFAULT_SERVICE: &str = "neuromesh-agent-ebpf-sensor";
pub const DEFAULT_SOURCE: &str = "neuromesh";
pub const DEFAULT_QUEUE_CAPACITY: usize = 8192;
pub const DEFAULT_METRICS_PORT: u16 = 9092;

pub const QUEUE_CAPACITY_ENV: &str = "NEUROMESH_DATADOG_QUEUE_CAPACITY";
pub const METRICS_PORT_ENV: &str = "NEUROMESH_DATADOG_METRICS_PORT";

/// Shared env used by ai-threat-detector — must never be read by this crate.
pub const FORBIDDEN_SHARED_KAFKA_GROUP_ENV: &str = "NEUROMESH_KAFKA_GROUP_ID";

#[derive(Debug, Clone)]
pub struct ForwarderConfig {
    pub logs_url: String,
    pub api_key: String,
    pub service: String,
    pub ddsource: String,
    pub kafka_brokers: Vec<String>,
    pub kafka_topic: String,
    pub kafka_group_id: String,
    pub queue_capacity: usize,
    pub metrics_port: u16,
}

impl ForwarderConfig {
    /// Returns `None` when Datadog forwarding is not fully configured (default-off).
    pub fn from_env() -> Option<Self> {
        let logs_url = resolve_logs_url()?;
        let api_key = load_api_key_file().ok()?;

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
            logs_url,
            api_key,
            service: std::env::var(DATADOG_SERVICE_ENV)
                .unwrap_or_else(|_| DEFAULT_SERVICE.to_string()),
            ddsource: std::env::var(DATADOG_SOURCE_ENV)
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

    pub fn load_api_key_from_env() -> Result<String> {
        load_api_key_file()
    }
}

fn resolve_logs_url() -> Option<String> {
    if let Some(url) = std::env::var(DATADOG_LOGS_URL_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return Some(url);
    }
    let site = std::env::var(DATADOG_SITE_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())?;
    intake_url_for_site(&site).ok()
}

/// Map a Datadog site identifier to Logs HTTP intake v2. Never defaults to US1.
pub fn intake_url_for_site(site: &str) -> Result<String> {
    let trimmed = site
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let site = trimmed.strip_prefix("app.").unwrap_or(trimmed);

    let host = match site {
        "us1" | "datadoghq.com" => "http-intake.logs.datadoghq.com",
        "us3" | "us3.datadoghq.com" => "http-intake.logs.us3.datadoghq.com",
        "us5" | "us5.datadoghq.com" => "http-intake.logs.us5.datadoghq.com",
        "eu" | "eu1" | "datadoghq.eu" => "http-intake.logs.datadoghq.eu",
        "ap1" | "ap1.datadoghq.com" => "http-intake.logs.ap1.datadoghq.com",
        "ap2" | "ap2.datadoghq.com" => "http-intake.logs.ap2.datadoghq.com",
        "uk1" | "uk1.datadoghq.com" => "http-intake.logs.uk1.datadoghq.com",
        "us1-fed" | "ddog-gov.com" => "http-intake.logs.ddog-gov.com",
        "us2-fed" | "us2.ddog-gov.com" => "http-intake.logs.us2.ddog-gov.com",
        other => {
            bail!("unknown Datadog site {other:?}; set {DATADOG_LOGS_URL_ENV} for a custom intake");
        }
    };
    Ok(format!("https://{host}/api/v2/logs"))
}

fn load_api_key_file() -> Result<String> {
    let path = std::env::var(DATADOG_API_KEY_FILE_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("{DATADOG_API_KEY_FILE_ENV} not set — Datadog Logs inactive")
        })?;

    let pb = PathBuf::from(&path);
    if !pb.is_absolute() {
        bail!("{DATADOG_API_KEY_FILE_ENV} must be an absolute path, got {path:?}");
    }

    let raw = std::fs::read_to_string(&pb)
        .with_context(|| format!("read {DATADOG_API_KEY_FILE_ENV} at {}", pb.display()))?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        bail!("{DATADOG_API_KEY_FILE_ENV} ({}) is empty", pb.display());
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn write_key(path: &std::path::Path, key: &str) {
        let mut f = std::fs::File::create(path).expect("create key file");
        f.write_all(key.as_bytes()).expect("write key");
    }

    fn clear_forwarder_env() {
        std::env::remove_var(DATADOG_SITE_ENV);
        std::env::remove_var(DATADOG_LOGS_URL_ENV);
        std::env::remove_var(DATADOG_API_KEY_FILE_ENV);
        std::env::remove_var(KAFKA_BROKERS_ENV);
        std::env::remove_var(KAFKA_TOPIC_ENV);
        std::env::remove_var(KAFKA_GROUP_ID_ENV);
        std::env::remove_var(FORBIDDEN_SHARED_KAFKA_GROUP_ENV);
    }

    #[test]
    fn kafka_group_identity_is_distinct_from_splunk_and_ai_detector() {
        assert_eq!(KAFKA_GROUP_ID_ENV, "NEUROMESH_DATADOG_KAFKA_GROUP_ID");
        assert_ne!(KAFKA_GROUP_ID_ENV, FORBIDDEN_SHARED_KAFKA_GROUP_ENV);
        assert_eq!(DEFAULT_KAFKA_GROUP, "datadog-forwarder");
        assert_ne!(DEFAULT_KAFKA_GROUP, "splunk-hec-forwarder");
        assert_ne!(DEFAULT_KAFKA_GROUP, "ai-threat-detector");
    }

    #[test]
    fn intake_url_is_site_derived_not_hardcoded_us1_only() {
        assert_eq!(
            intake_url_for_site("datadoghq.eu").unwrap(),
            "https://http-intake.logs.datadoghq.eu/api/v2/logs"
        );
        assert_eq!(
            intake_url_for_site("us3.datadoghq.com").unwrap(),
            "https://http-intake.logs.us3.datadoghq.com/api/v2/logs"
        );
        assert_eq!(
            intake_url_for_site("us1").unwrap(),
            "https://http-intake.logs.datadoghq.com/api/v2/logs"
        );
        assert!(intake_url_for_site("not-a-site").is_err());
    }

    #[test]
    fn missing_api_key_file_yields_inactive_not_panic() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_forwarder_env();

        let dir = std::env::temp_dir().join(format!("nm-dd-key-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");

        let missing = dir.join("missing-key");
        std::env::set_var(
            DATADOG_API_KEY_FILE_ENV,
            missing.to_string_lossy().to_string(),
        );
        assert!(ForwarderConfig::load_api_key_from_env().is_err());
        assert!(ForwarderConfig::from_env().is_none());

        clear_forwarder_env();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_env_none_without_site_or_kafka() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_forwarder_env();
        assert!(ForwarderConfig::from_env().is_none());
    }

    #[test]
    fn from_env_ignores_shared_kafka_group_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        clear_forwarder_env();

        let dir = std::env::temp_dir().join(format!("nm-dd-key-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let key_path = dir.join("dd.key");
        write_key(&key_path, "test-dd-key\n");

        std::env::set_var(DATADOG_SITE_ENV, "datadoghq.eu");
        std::env::set_var(
            DATADOG_API_KEY_FILE_ENV,
            key_path.to_string_lossy().to_string(),
        );
        std::env::set_var(KAFKA_BROKERS_ENV, "localhost:9092");
        std::env::set_var(FORBIDDEN_SHARED_KAFKA_GROUP_ENV, "ai-threat-detector");

        let cfg = ForwarderConfig::from_env().expect("configured");
        assert_eq!(cfg.api_key, "test-dd-key");
        assert_eq!(cfg.kafka_group_id, DEFAULT_KAFKA_GROUP);
        assert_eq!(
            cfg.logs_url,
            "https://http-intake.logs.datadoghq.eu/api/v2/logs"
        );

        clear_forwarder_env();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
