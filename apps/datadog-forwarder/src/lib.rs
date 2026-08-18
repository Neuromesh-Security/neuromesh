//! Kafka slow-path Datadog Logs forwarder — fully decoupled from agent enforcement.
//!
//! This crate intentionally has **no dependency** on `agent-ebpf-sensor`, `aya`, or
//! LSM/policy-sync code paths. Alerts are consumed from Kafka only.

pub mod config;
pub mod envelope;
pub mod forwarder;
pub mod logs;
pub mod metrics;

pub use config::ForwarderConfig;
pub use envelope::TelemetryEnvelope;
pub use forwarder::{DatadogForwarder, ForwarderHandle, ForwarderStats};
pub use logs::{build_datadog_log, DatadogLogClient, DatadogLogItem};
pub use metrics::DdMetrics;

/// Compile-time isolation marker: forwarder must never link agent/eBPF crates.
pub const ISOLATION: &str = "datadog-forwarder-is-kafka-consumer-only";
