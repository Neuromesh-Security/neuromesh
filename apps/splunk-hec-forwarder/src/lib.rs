//! Kafka slow-path Splunk HEC forwarder — fully decoupled from agent enforcement.
//!
//! This crate intentionally has **no dependency** on `agent-ebpf-sensor`, `aya`, or
//! LSM/policy-sync code paths. Alerts are consumed from Kafka only.

pub mod config;
pub mod envelope;
pub mod forwarder;
pub mod hec;
pub mod metrics;

pub use config::ForwarderConfig;
pub use envelope::TelemetryEnvelope;
pub use forwarder::{ForwarderHandle, ForwarderStats, SplunkForwarder};
pub use hec::{build_hec_event, HecEventBody, SplunkHecClient};
pub use metrics::HecMetrics;

/// Compile-time isolation marker: forwarder must never link agent/eBPF crates.
pub const ISOLATION: &str = "splunk-hec-forwarder-is-kafka-consumer-only";
