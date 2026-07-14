//! User-space detection and telemetry pipeline (kernel-independent test surface).

pub mod bpf_pin;
pub mod ingestion;
pub mod mocks;
pub mod normalizer;
pub mod pipeline;
pub mod rules;
pub mod shutdown;
pub mod telemetry_stream;
pub mod wasm_policy;

pub mod monitoring;

pub use bpf_pin::{load_with_map_pinning, pin_root, DEFAULT_BPF_PIN_ROOT};
pub use shutdown::wait_for_shutdown_signal;

pub use normalizer::{BehaviorAlert, DataNormalizer, SEVERITY_BEHAVIOR_ALERT};
pub use pipeline::{PipelineOutput, TelemetryPipeline};
pub use rules::{RuleEngine, RuleVerdict, SiemAlert, SEVERITY_CRITICAL_ALERT};
