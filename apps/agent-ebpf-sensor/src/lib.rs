//! User-space detection and telemetry pipeline (kernel-independent test surface).

pub mod ingestion;
pub mod mocks;
pub mod normalizer;
pub mod pipeline;
pub mod rules;
pub mod telemetry_stream;
pub mod wasm_policy;

pub mod monitoring;

pub use normalizer::{BehaviorAlert, DataNormalizer, SEVERITY_BEHAVIOR_ALERT};
pub use pipeline::{PipelineOutput, TelemetryPipeline};
pub use rules::{RuleEngine, RuleVerdict, SiemAlert, SEVERITY_CRITICAL_ALERT};
