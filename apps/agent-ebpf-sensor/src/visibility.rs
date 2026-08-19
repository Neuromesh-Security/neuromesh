//! Visibility + observability: process/network monitors, integrity, metrics, ringbuf.

use crate::startup::{network_filter_bpf, sys_exec_bpf, EnforcementArmed};
use agent_ebpf_sensor::ingestion;
use agent_ebpf_sensor::load_with_map_pinning;
use agent_ebpf_sensor::monitoring::{start_network_monitor, start_process_monitor};
use agent_ebpf_sensor::observability::{
    spawn_health_monitor, spawn_metrics_server, AgentHealthProbe,
};
use agent_ebpf_sensor::pipeline::TelemetryPipeline;
use agent_ebpf_sensor::telemetry_stream::{self, TelemetryStreamHandle};
use agent_ebpf_sensor::wasm_policy::WasmPolicyEngine;
use anyhow::Context;
use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
use aya::Ebpf;
use neuromesh_common::{
    SecurityTelemetryEvent, TelemetryHealthStats, RATE_LIMIT_DROPS_MAP, TELEMETRY_RINGBUF_MAP,
    TELEMETRY_STATS_MAP,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

pub struct AgentRuntime {
    pub shutdown: tokio_util::sync::CancellationToken,
    pub bpf_pin_root: PathBuf,
    pub async_ring: AsyncFd<RingBuf<MapData>>,
    pub stats_map: Array<MapData, TelemetryHealthStats>,
    pub pipeline: TelemetryPipeline,
    pub telemetry_stream: TelemetryStreamHandle,
    pub detection_rx: mpsc::Receiver<SecurityTelemetryEvent>,
    pub _wasm_policy: WasmPolicyEngine,
    pub _process_bpf: Ebpf,
    pub _network_bpf: Ebpf,
    pub _enforcement_bpf: Ebpf,
    pub _integrity: tokio::task::JoinHandle<()>,
    pub _lsm_link_pin: aya::programs::links::PinnedLink,
    pub _policy_sync: tokio::task::JoinHandle<()>,
    pub _correlator: Option<tokio::task::JoinHandle<()>>,
}

pub async fn arm_visibility_and_observability(
    armed: EnforcementArmed,
) -> Result<AgentRuntime, anyhow::Error> {
    let EnforcementArmed {
        shutdown,
        bpf_pin_root,
        enf_paths,
        policy_sync_state,
        mut enforcement_bpf,
        metrics,
        _lsm_link_pin,
        _policy_sync,
        _correlator,
    } = armed;

    let correlation_ingestion = ingestion::spawn_from_env().await;

    let mut process_bpf = load_with_map_pinning(sys_exec_bpf(), &bpf_pin_root)?;

    let rate_limit_drops = PerCpuArray::try_from(
        process_bpf
            .take_map(RATE_LIMIT_DROPS_MAP)
            .with_context(|| {
                format!("BPF map `{RATE_LIMIT_DROPS_MAP}` missing from object file")
            })?,
    )?;

    // Issue #44 Phase 2 + #75: periodic runtime integrity (exe + on-disk + pins).
    // Additive after successful pin/attestation — does not alter Phase 1 or PR #72.
    let integrity_cfg = agent_ebpf_sensor::integrity::IntegrityConfig::from_env(
        &bpf_pin_root,
        PathBuf::from("/proc/self/exe"),
    )
    .context("failed to initialize runtime integrity monitor (Issue #44 Phase 2)")?;
    let _integrity = agent_ebpf_sensor::integrity::spawn_integrity_monitor(
        integrity_cfg,
        Arc::clone(&metrics),
        shutdown.clone(),
    );

    let (detection_tx, detection_rx) = mpsc::channel::<SecurityTelemetryEvent>(4096);

    let correlation = start_process_monitor(
        &mut process_bpf,
        shutdown.clone(),
        Arc::clone(&metrics),
        Some(detection_tx),
    )
    .await?;

    spawn_health_monitor(rate_limit_drops, Arc::clone(&metrics), shutdown.clone());
    let health_probe = Arc::new(AgentHealthProbe::new(
        enf_paths,
        Arc::clone(&policy_sync_state),
    ));
    spawn_metrics_server(Arc::clone(&metrics), health_probe, shutdown.clone()).await?;

    let mut network_bpf = Ebpf::load(network_filter_bpf())?;
    start_network_monitor(
        &mut network_bpf,
        Arc::clone(&correlation),
        correlation_ingestion,
        shutdown.clone(),
    )
    .await?;

    let stats_map = Array::try_from(
        enforcement_bpf
            .take_map(TELEMETRY_STATS_MAP)
            .ok_or_else(|| anyhow::anyhow!("{TELEMETRY_STATS_MAP} map missing from eBPF object"))?,
    )?;
    let telemetry_map = RingBuf::try_from(
        enforcement_bpf
            .take_map(TELEMETRY_RINGBUF_MAP)
            .ok_or_else(|| {
                anyhow::anyhow!("{TELEMETRY_RINGBUF_MAP} map missing from eBPF object")
            })?,
    )?;
    let async_ring = AsyncFd::new(telemetry_map)?;
    let pipeline = TelemetryPipeline::new();
    let telemetry_stream = telemetry_stream::spawn_from_env().await;
    let _wasm_policy = WasmPolicyEngine::new();

    Ok(AgentRuntime {
        shutdown,
        bpf_pin_root,
        async_ring,
        stats_map,
        pipeline,
        telemetry_stream,
        detection_rx,
        _wasm_policy,
        _process_bpf: process_bpf,
        _network_bpf: network_bpf,
        _enforcement_bpf: enforcement_bpf,
        _integrity,
        _lsm_link_pin,
        _policy_sync,
        _correlator,
    })
}
