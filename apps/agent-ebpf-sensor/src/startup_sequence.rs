//! Frozen orchestrator startup log contract.
//!
//! These strings and the `ORCHESTRATOR_MAIN_CALLS` list are the equivalence
//! proof that `src/main.rs` is a thin dispatcher: same messages, same order.
//! Reordering a call in `main.rs` or changing a banner string fails CI.

use log::info;
use neuromesh_common::{PROCESS_EVENTS_MAP, RATE_LIMIT_BUCKET_MAP, RATE_LIMIT_DROPS_MAP};
use std::path::Path;

/// Calls `src/main.rs` must make, in this order. Parsed by unit test.
pub const ORCHESTRATOR_MAIN_CALLS: &[&str] = &[
    "startup::init_tracing()",
    "startup_sequence::log_initializing()",
    "startup::attest_and_load_enforcement(",
    "startup::arm_correlator_deny_and_lsm(",
    "visibility::arm_visibility_and_observability(",
    "startup_sequence::emit_runtime_armed(",
    "event_loop::run(",
];

pub const LOG_INITIALIZING: &str = "🚀 [Neuromesh] Initializing Enterprise Agent...";
pub const LOG_ATTESTATION_OK: &str =
    "🔏 Bytecode attestation verified (signed manifest + embedded digests match)";
pub const LOG_BTF_OFFSETS_PREFIX: &str =
    "🔎 Resolved kernel-specific struct offsets via BTF: linux_binprm.filename=";
pub const LOG_DENY_BOOTSTRAP: &str =
    "🛡️ Path-prefix deny list: cold bootstrap (fail-closed defaults)";
pub const LOG_DENY_RESUME_PREFIX: &str = "🛡️ Path-prefix deny list: resuming ";
pub const LOG_LSM_PINNED_PREFIX: &str = "📌 LSM link pinned at ";

pub const LOG_PROCESS_VISIBILITY: &str = "👁️ Process visibility armed via sys_enter_execve + sys_enter_execveat tracepoints (execveat attach also covers fexecve).";
pub const LOG_NETWORK_VISIBILITY: &str = "🌐 Network visibility armed via tcp_connect kprobe.";
pub const LOG_CORRELATION: &str =
    "🔗 Lock-free correlation engine armed (DashMap PID → process name).";
pub const LOG_CORRELATION_KAFKA: &str =
    "📨 Correlation Kafka ingestion armed (bounded MPSC → idempotent rdkafka).";
pub const LOG_XDR: &str =
    "🛡️ XDR enforcement armed. LSM bprm_check_security active blocking enabled.";
pub const LOG_DETECTION_BRAIN: &str =
    "⚡ Detection brain armed. RuleEngine + DataNormalizer active on ExecEvent v1 streams...";
pub const LOG_PROMETHEUS: &str = "📈 Prometheus /metrics exporter armed (default port 9090, override via NEUROMESH_METRICS_PORT)";
pub const LOG_KAFKA_ARMED: &str = "📡 Kafka Slow Path armed (topic: neuromesh.telemetry.v1)";
pub const LOG_KAFKA_DISABLED: &str =
    "📡 Kafka Slow Path disabled (set NEUROMESH_KAFKA_BROKERS to enable)";

pub fn log_initializing() {
    info!("{LOG_INITIALIZING}");
}

pub fn log_attestation_ok() {
    info!("{LOG_ATTESTATION_OK}");
}

pub fn log_btf_offsets(filename: u64, real_parent: u64, tgid: u64) {
    info!(
        "{LOG_BTF_OFFSETS_PREFIX}{filename} \
         task_struct.real_parent={real_parent} task_struct.tgid={tgid}"
    );
}

pub fn log_deny_bootstrap() {
    info!("{LOG_DENY_BOOTSTRAP}");
}

pub fn log_deny_resume(count: u32) {
    info!(
        "{LOG_DENY_RESUME_PREFIX}{count} pinned entries (skip bootstrap; \
         STALE until policy sync)"
    );
}

pub fn log_lsm_pinned(path: &Path) {
    info!(
        "{LOG_LSM_PINNED_PREFIX}{} (enforcement survives agent process exit)",
        path.display()
    );
}

pub fn log_manual_identity_seeds(count: usize) {
    info!(
        "⚠️ Manual identity cgroup seeds applied (lab/test): {count} id(s) — VALID still requires fresh PE identity section"
    );
}

pub fn map_pinning_log_line(pin_root: &Path) -> String {
    format!(
        "📌 eBPF map pinning active under {} ({PROCESS_EVENTS}, {RATE_LIMIT_BUCKET})",
        pin_root.display(),
        PROCESS_EVENTS = PROCESS_EVENTS_MAP,
        RATE_LIMIT_BUCKET = RATE_LIMIT_BUCKET_MAP,
    )
}

pub fn health_monitor_log_line() -> String {
    format!(
        "🩺 Health monitor armed (kernel {RATE_LIMIT_DROPS_MAP} + user-space channel backpressure)"
    )
}

/// Happy-path post-wiring banner, exact order from pre-refactor `main.rs`.
pub fn runtime_armed_log_lines(pin_root: &Path, kafka_brokers_set: bool) -> Vec<String> {
    let mut lines = vec![
        LOG_PROCESS_VISIBILITY.to_string(),
        LOG_NETWORK_VISIBILITY.to_string(),
        LOG_CORRELATION.to_string(),
        LOG_CORRELATION_KAFKA.to_string(),
        LOG_XDR.to_string(),
        LOG_DETECTION_BRAIN.to_string(),
        map_pinning_log_line(pin_root),
        LOG_PROMETHEUS.to_string(),
        health_monitor_log_line(),
    ];
    if kafka_brokers_set {
        lines.push(LOG_KAFKA_ARMED.to_string());
    } else {
        lines.push(LOG_KAFKA_DISABLED.to_string());
    }
    lines
}

pub fn emit_runtime_armed(pin_root: &Path) {
    let kafka = std::env::var("NEUROMESH_KAFKA_BROKERS").is_ok();
    for line in runtime_armed_log_lines(pin_root, kafka) {
        info!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Frozen copy of the pre-refactor banner (main.rs before this split).
    const FROZEN_ARMED_BANNER_NO_KAFKA: &[&str] = &[
        "👁️ Process visibility armed via sys_enter_execve + sys_enter_execveat tracepoints (execveat attach also covers fexecve).",
        "🌐 Network visibility armed via tcp_connect kprobe.",
        "🔗 Lock-free correlation engine armed (DashMap PID → process name).",
        "📨 Correlation Kafka ingestion armed (bounded MPSC → idempotent rdkafka).",
        "🛡️ XDR enforcement armed. LSM bprm_check_security active blocking enabled.",
        "⚡ Detection brain armed. RuleEngine + DataNormalizer active on ExecEvent v1 streams...",
        "📌 eBPF map pinning active under /sys/fs/bpf/neuromesh (PROCESS_EVENTS, RLIMIT_BUCKET)",
        "📈 Prometheus /metrics exporter armed (default port 9090, override via NEUROMESH_METRICS_PORT)",
        "🩺 Health monitor armed (kernel RLIMIT_DROPS + user-space channel backpressure)",
        "📡 Kafka Slow Path disabled (set NEUROMESH_KAFKA_BROKERS to enable)",
    ];

    #[test]
    fn runtime_armed_banner_matches_frozen_pre_refactor_order() {
        let pin = Path::new("/sys/fs/bpf/neuromesh");
        let got = runtime_armed_log_lines(pin, false);
        assert_eq!(got.len(), FROZEN_ARMED_BANNER_NO_KAFKA.len());
        for (i, (got_line, frozen)) in got.iter().zip(FROZEN_ARMED_BANNER_NO_KAFKA).enumerate() {
            assert_eq!(
                got_line, frozen,
                "armed banner line {i} drifted or reordered"
            );
        }
    }

    #[test]
    fn kafka_armed_line_is_last_when_brokers_set() {
        let pin = Path::new("/sys/fs/bpf/neuromesh");
        let got = runtime_armed_log_lines(pin, true);
        assert_eq!(got.last().map(String::as_str), Some(LOG_KAFKA_ARMED));
        assert_eq!(got.len(), FROZEN_ARMED_BANNER_NO_KAFKA.len());
    }

    #[test]
    fn orchestrator_main_invokes_phases_in_documented_order() {
        let src = include_str!("main.rs");
        let mut last = 0usize;
        for (i, marker) in ORCHESTRATOR_MAIN_CALLS.iter().enumerate() {
            let pos = src
                .find(marker)
                .unwrap_or_else(|| panic!("main.rs missing orchestrator call {marker:?}"));
            assert!(
                pos > last,
                "orchestrator call {i} ({marker}) appears before previous phase in main.rs \
                 (pos={pos} last={last}) — bootstrap order changed"
            );
            last = pos;
        }
    }

    /// Frozen pre-refactor `info!` bodies from origin/main `main.rs` (not the
    /// armed banner). Prefixes are used where the original line interpolated.
    const FROZEN_BOOTSTRAP_LOGS: &[&str] = &[
        "🚀 [Neuromesh] Initializing Enterprise Agent...",
        "🔏 Bytecode attestation verified (signed manifest + embedded digests match)",
        "🔎 Resolved kernel-specific struct offsets via BTF: linux_binprm.filename=",
        "🛡️ Path-prefix deny list: cold bootstrap (fail-closed defaults)",
        "🛡️ Path-prefix deny list: resuming ",
        "📌 LSM link pinned at ",
    ];

    #[test]
    fn bootstrap_log_constants_match_frozen_pre_refactor() {
        assert_eq!(LOG_INITIALIZING, FROZEN_BOOTSTRAP_LOGS[0]);
        assert_eq!(LOG_ATTESTATION_OK, FROZEN_BOOTSTRAP_LOGS[1]);
        assert_eq!(LOG_BTF_OFFSETS_PREFIX, FROZEN_BOOTSTRAP_LOGS[2]);
        assert_eq!(LOG_DENY_BOOTSTRAP, FROZEN_BOOTSTRAP_LOGS[3]);
        assert_eq!(LOG_DENY_RESUME_PREFIX, FROZEN_BOOTSTRAP_LOGS[4]);
        assert_eq!(LOG_LSM_PINNED_PREFIX, FROZEN_BOOTSTRAP_LOGS[5]);
    }

    #[test]
    fn startup_rs_emits_attestation_btf_deny_lsm_logs_in_order() {
        let startup = include_str!("startup.rs");
        let markers = [
            "startup_sequence::log_attestation_ok",
            "startup_sequence::log_btf_offsets",
            "startup_sequence::log_manual_identity_seeds",
            "startup_sequence::log_deny_bootstrap",
            "startup_sequence::log_deny_resume",
            "startup_sequence::log_lsm_pinned",
        ];
        assert_source_markers_in_order("startup.rs", startup, &markers);
    }

    #[test]
    fn startup_rs_fail_closed_calls_stay_in_pre_refactor_order() {
        let startup = include_str!("startup.rs");
        let markers = [
            "bytecode_attestation::verify_startup",
            "EbpfLoader::new",
            "AgentMetrics::new",
            "identity_correlator::spawn_identity_correlator",
            "deny_map_seed_plan(maps_preexisted",
            "lsm_program.load(\"bprm_check_security\"",
            "attach_and_pin_lsm_fail_closed(lsm_program",
            "policy_sync::spawn_policy_sync",
        ];
        assert_source_markers_in_order("startup.rs", startup, &markers);
    }

    #[test]
    fn visibility_rs_arms_monitors_in_pre_refactor_order() {
        let vis = include_str!("visibility.rs");
        let markers = [
            "ingestion::spawn_from_env().await",
            "load_with_map_pinning(sys_exec_bpf()",
            "spawn_integrity_monitor(",
            "start_process_monitor(",
            "spawn_health_monitor(rate_limit_drops",
            "spawn_metrics_server(Arc::clone(&metrics)",
            "start_network_monitor(",
            ".take_map(TELEMETRY_STATS_MAP)",
            ".take_map(TELEMETRY_RINGBUF_MAP)",
            "AsyncFd::new(",
            "TelemetryPipeline::new()",
            "telemetry_stream::spawn_from_env().await",
            "WasmPolicyEngine::new()",
        ];
        assert_source_markers_in_order("visibility.rs", vis, &markers);
    }

    #[test]
    fn event_loop_rs_select_arms_match_pre_refactor_order() {
        let src = include_str!("event_loop.rs");
        let markers = [
            "shutdown.cancelled()",
            "wait_for_shutdown_signal() =>",
            "stats_interval.tick() =>",
            "async_ring.async_io_mut",
            "detection_rx.recv()",
            "graceful shutdown complete — BPF links released",
        ];
        assert_source_markers_in_order("event_loop.rs", src, &markers);
    }

    fn assert_source_markers_in_order(file: &str, src: &str, markers: &[&str]) {
        let mut last = 0usize;
        for (i, marker) in markers.iter().enumerate() {
            let pos = src
                .find(marker)
                .unwrap_or_else(|| panic!("{file} missing marker {marker:?}"));
            assert!(
                pos >= last,
                "{file} marker {i} ({marker}) reordered (pos={pos} last={last})"
            );
            last = pos;
        }
    }
}
