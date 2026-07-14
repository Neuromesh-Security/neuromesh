//! Shared stress-test profiles for manual execve load validation.

/// Target throughput tiers for enterprise load validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StressTier {
    /// ~100k execve/sec sustained burst target.
    Standard,
    /// ~500k execve/sec sustained burst target (kernel token-bucket ceiling).
    Extreme,
}

impl StressTier {
    pub fn from_env() -> Self {
        match std::env::var("EXECVE_STRESS_TIER")
            .ok()
            .map(|value| value.to_ascii_lowercase())
            .as_deref()
        {
            Some("extreme") | Some("500k") => Self::Extreme,
            Some("standard") | Some("100k") => Self::Standard,
            _ => Self::Standard,
        }
    }

    pub fn target_eps(&self) -> u64 {
        match self {
            Self::Standard => 100_000,
            Self::Extreme => 500_000,
        }
    }

    pub fn default_workers(&self) -> usize {
        match self {
            Self::Standard => 128,
            Self::Extreme => 512,
        }
    }

    pub fn default_duration_secs(&self) -> u64 {
        match self {
            Self::Standard => 30,
            Self::Extreme => 60,
        }
    }
}

/// Chaos mode hints for paired agent-side configuration during manual runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChaosHints {
    pub ringbuf_overflow: bool,
    pub userspace_memory_pressure: bool,
    pub abrupt_termination: bool,
}

impl ChaosHints {
    pub fn from_env() -> Self {
        let enabled = std::env::var("EXECVE_STRESS_CHAOS")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
        Self {
            ringbuf_overflow: enabled,
            userspace_memory_pressure: enabled,
            abrupt_termination: enabled,
        }
    }

    pub fn log_guidance(&self) {
        if !self.ringbuf_overflow && !self.userspace_memory_pressure && !self.abrupt_termination {
            return;
        }

        eprintln!("[execve-stress] chaos mode enabled — configure agent before burst:");
        if self.userspace_memory_pressure {
            eprintln!(
                "  NEUROMESH_PROCESS_CHANNEL_CAPACITY=64   # force MPSC backpressure / ebpf_events_dropped_total"
            );
        }
        if self.ringbuf_overflow {
            eprintln!(
                "  watch RATE_LIMIT_DROPS via /metrics or neuromesh::health logs (kernel token bucket)"
            );
        }
        if self.abrupt_termination {
            eprintln!("  send SIGTERM mid-burst; agent must drain and exit without panic");
        }
    }
}
