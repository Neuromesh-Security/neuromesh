//! Enterprise observability: health sampling and Prometheus export.

pub mod health;
pub mod healthz;
pub mod metrics;
pub mod prometheus;

pub use health::{spawn_health_monitor, sum_rate_limit_drops};
pub use healthz::{AgentHealthProbe, HealthReport};
pub use metrics::{AgentMetrics, RATE_LIMIT_DROPS_MAP};
pub use prometheus::spawn_metrics_server;
