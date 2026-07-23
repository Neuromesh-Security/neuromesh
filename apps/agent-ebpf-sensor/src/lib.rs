//! User-space detection and telemetry pipeline (kernel-independent test surface).

pub mod bpf_pin;
pub mod btf_offsets;
pub mod bytecode_attestation;
pub mod ingestion;
pub mod integrity;
pub mod lsm_decision;
pub mod lsm_pin;
pub mod mocks;
pub mod normalizer;
pub mod path_deny;
pub mod pipeline;
pub mod policy_sync;
pub mod rules;
pub mod shutdown;
pub mod telemetry_stream;
pub mod wasm_policy;

pub mod monitoring;

#[cfg(feature = "orchestrator")]
pub mod observability;

pub use bpf_pin::{load_with_map_pinning, pin_root, DEFAULT_BPF_PIN_ROOT};
pub use shutdown::wait_for_shutdown_signal;

#[cfg(feature = "orchestrator")]
pub use observability::{
    spawn_health_monitor, spawn_metrics_server, AgentMetrics, RATE_LIMIT_DROPS_MAP,
};

pub use normalizer::{BehaviorAlert, DataNormalizer, SEVERITY_BEHAVIOR_ALERT};
pub use pipeline::{PipelineOutput, TelemetryPipeline};
pub use rules::{RuleEngine, RuleVerdict, SiemAlert, SEVERITY_CRITICAL_ALERT};
