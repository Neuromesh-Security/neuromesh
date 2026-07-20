use agent_ebpf_sensor::btf_offsets::{self, ResolvedOffsets};
use agent_ebpf_sensor::bytecode_attestation::{self, EmbeddedArtifact};
use agent_ebpf_sensor::ingestion;
use agent_ebpf_sensor::monitoring::ringbuf_decode::decode_exec_event;
use agent_ebpf_sensor::monitoring::{
    exec_event_to_security_telemetry, start_network_monitor, start_process_monitor,
};
use agent_ebpf_sensor::observability::{
    spawn_health_monitor, spawn_metrics_server, AgentMetrics, RATE_LIMIT_DROPS_MAP,
};
use agent_ebpf_sensor::lsm_pin::{
    self, attach_and_pin_lsm_fail_closed, classify_enforcement_pins, deny_map_seed_plan,
    enforcement_pin_paths, policy_state_for_pinned_resume, DenyMapSeedPlan, EnforcementPinState,
    PINNED_ENFORCEMENT_MAPS,
};
use agent_ebpf_sensor::path_deny::{self, PathDenyMaps};
use agent_ebpf_sensor::pipeline::TelemetryPipeline;
use agent_ebpf_sensor::policy_sync;
use agent_ebpf_sensor::rules::RuleEngine;
use agent_ebpf_sensor::telemetry_stream::{self, TelemetryStreamHandle};
use agent_ebpf_sensor::wasm_policy::WasmPolicyEngine;
use agent_ebpf_sensor::{load_with_map_pinning, pin_root, wait_for_shutdown_signal};
use anyhow::Context;
use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};
use log::info;
use neuromesh_common::{
    PathDenyEntry, SecurityTelemetryEvent, TelemetryHealthStats, PATH_DENY_COUNT_MAP,
    PATH_DENY_LIST_MAP, TELEMETRY_STATS_INDEX,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio_util::sync::CancellationToken;

const SYS_EXEC_BPF: &[u8] = include_bytes!("../target/bpf/sys_exec.bpf.o");
const NETWORK_FILTER_BPF: &[u8] = include_bytes!("../target/bpf/network_filter.bpf.o");

/// Drain window for monitor tasks after cancellation before dropping BPF links.
const SHUTDOWN_DRAIN_MS: u64 = 500;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    env_logger::init();

    info!("🚀 [Neuromesh] Initializing Enterprise Agent...");

    let shutdown = CancellationToken::new();

    let enforcement_bpf_data = include_bytes!(env!("NEUROMESH_EBPF_ENFORCEMENT_BYTECODE"));

    // Issue #44 Phase 1: Cosign-signed bytecode manifest verification.
    // Gates the *entire* BPF load sequence (C objects + LSM enforcement ELF).
    // Must run before any EbpfLoader::load / Ebpf::load / load_with_map_pinning.
    // Tamper-evidence only — see bytecode_attestation module docs. Fail-closed:
    // no skip flag, no partial load, no unverified fallback.
    bytecode_attestation::verify_startup(&[
        EmbeddedArtifact {
            name: "sys_exec.bpf.o",
            bytes: SYS_EXEC_BPF,
        },
        EmbeddedArtifact {
            name: "network_filter.bpf.o",
            bytes: NETWORK_FILTER_BPF,
        },
        EmbeddedArtifact {
            name: "agent-ebpf-sensor-ebpf",
            bytes: enforcement_bpf_data,
        },
    ])
    .context(
        "bytecode attestation failed — refusing to load any eBPF object (fail-closed); \
         see error for specific artifact/check that failed",
    )?;
    info!("🔏 Bytecode attestation verified (signed manifest + embedded digests match)");

    // BTF is fetched once and used for two purposes: (1) resolving the three
    // kernel-specific struct field offsets the LSM enforcement hook needs
    // (see `btf_offsets.rs`), injected below before the program is loaded,
    // and (2) the LSM attach call's own BTF argument. Resolution happens
    // strictly before `EbpfLoader::load` — if it fails for any reason, the
    // enforcement program is never loaded and the agent aborts startup
    // (fail-closed; there is no hardcoded fallback offset left to fall back to).
    let btf = Btf::from_sys_fs().context(
        "failed to load kernel BTF from /sys/kernel/btf/vmlinux — required to resolve \
         task_struct/linux_binprm field offsets for the LSM enforcement hook; refusing to \
         start (fail-closed)",
    )?;
    let resolved_offsets = resolve_enforcement_offsets(&btf)?;
    info!(
        "🔎 Resolved kernel-specific struct offsets via BTF: linux_binprm.filename={} \
         task_struct.real_parent={} task_struct.tgid={}",
        resolved_offsets.bprm_filename_offset,
        resolved_offsets.task_real_parent_offset,
        resolved_offsets.task_tgid_offset
    );

    // Issue #44 PR A: pin LSM link + PATH_DENY_* so enforcement survives agent exit.
    // Fail-closed if bpffs/pins are unavailable — never boot with ephemeral-only attach.
    let bpf_pin_root = pin_root();
    agent_ebpf_sensor::bpf_pin::prepare_pin_directory(&bpf_pin_root).context(
        "bpffs pin directory unavailable — refusing to start without ability to pin LSM \
         enforcement (fail-closed; see Issue #44)",
    )?;
    let pin_state = classify_enforcement_pins(&bpf_pin_root);
    if matches!(pin_state, EnforcementPinState::InconsistentLinkWithoutMaps) {
        anyhow::bail!(
            "inconsistent enforcement pins under {}: LSM link pin exists without \
             {PATH_DENY_LIST_MAP}/{PATH_DENY_COUNT_MAP} — refuse start (fail-closed); \
             remove {LSM} or restore deny-map pins",
            bpf_pin_root.display(),
            LSM = lsm_pin::LSM_LINK_PIN_NAME,
        );
    }
    let maps_preexisted = matches!(pin_state, EnforcementPinState::MapsReady { .. });
    let enf_paths = enforcement_pin_paths(&bpf_pin_root);

    let mut enforcement_loader = EbpfLoader::new();
    enforcement_loader
        .override_global(
            "BPRM_FILENAME_OFFSET",
            &resolved_offsets.bprm_filename_offset,
            true,
        )
        .override_global(
            "TASK_REAL_PARENT_OFFSET",
            &resolved_offsets.task_real_parent_offset,
            true,
        )
        .override_global("TASK_TGID_OFFSET", &resolved_offsets.task_tgid_offset, true);
    for map_name in PINNED_ENFORCEMENT_MAPS {
        enforcement_loader.map_pin_path(*map_name, bpf_pin_root.join(map_name));
    }
    let mut enforcement_bpf = enforcement_loader.load(enforcement_bpf_data).context(
        "failed to load enforcement eBPF object with BTF-resolved offsets injected — \
         refusing to start (fail-closed)",
    )?;

    let deny_list = Array::<MapData, PathDenyEntry>::try_from(
        enforcement_bpf
            .take_map(PATH_DENY_LIST_MAP)
            .ok_or_else(|| anyhow::anyhow!("{PATH_DENY_LIST_MAP} map missing from eBPF object"))?,
    )?;
    let deny_count = Array::<MapData, u32>::try_from(
        enforcement_bpf
            .take_map(PATH_DENY_COUNT_MAP)
            .ok_or_else(|| anyhow::anyhow!("{PATH_DENY_COUNT_MAP} map missing from eBPF object"))?,
    )?;
    let mut deny_maps = PathDenyMaps {
        list: deny_list,
        count: deny_count,
    };

    let active_count = lsm_pin::active_deny_count(&deny_maps)?;
    let seed_plan = deny_map_seed_plan(maps_preexisted, active_count)?;
    let policy_state = match seed_plan {
        DenyMapSeedPlan::Bootstrap => {
            info!("🛡️ Path-prefix deny list: cold bootstrap (fail-closed defaults)");
            path_deny::bootstrap_deny_maps(&mut deny_maps)
                .context("failed to bootstrap path-prefix deny list (fail-closed)")?
        }
        DenyMapSeedPlan::ResumePinned { count } => {
            info!(
                "🛡️ Path-prefix deny list: resuming {} pinned entries (skip bootstrap; \
                 STALE until policy sync)",
                count
            );
            policy_state_for_pinned_resume()
        }
    };

    let lsm_program: &mut Lsm = enforcement_bpf
        .program_mut("neuromesh_lsm_exec_guard")
        .ok_or_else(|| anyhow::anyhow!("neuromesh_lsm_exec_guard program missing"))?
        .try_into()?;
    lsm_program.load("bprm_check_security", &btf)?;
    // Keep pinned link FD alive for process lifetime (pin file is the survival
    // mechanism across kill -9; holding FD is belt-and-suspenders while running).
    let _lsm_link_pin = attach_and_pin_lsm_fail_closed(lsm_program, &bpf_pin_root)?;
    info!(
        "📌 LSM link pinned at {} (enforcement survives agent process exit)",
        enf_paths.link.display()
    );

    let _policy_sync = policy_sync::spawn_policy_sync(deny_maps, policy_state, shutdown.clone());

    let correlation_ingestion = ingestion::spawn_from_env().await;

    let mut process_bpf = load_with_map_pinning(SYS_EXEC_BPF, &bpf_pin_root)?;

    let metrics = AgentMetrics::new()?;
    let rate_limit_drops = PerCpuArray::try_from(
        process_bpf
            .take_map(RATE_LIMIT_DROPS_MAP)
            .with_context(|| {
                format!("BPF map `{RATE_LIMIT_DROPS_MAP}` missing from object file")
            })?,
    )?;

    let (detection_tx, mut detection_rx) =
        tokio::sync::mpsc::channel::<SecurityTelemetryEvent>(4096);

    let correlation = start_process_monitor(
        &mut process_bpf,
        shutdown.clone(),
        Arc::clone(&metrics),
        Some(detection_tx),
    )
    .await?;

    spawn_health_monitor(rate_limit_drops, Arc::clone(&metrics), shutdown.clone());
    spawn_metrics_server(Arc::clone(&metrics), shutdown.clone()).await?;

    let mut network_bpf = Ebpf::load(NETWORK_FILTER_BPF)?;
    start_network_monitor(
        &mut network_bpf,
        Arc::clone(&correlation),
        correlation_ingestion,
        shutdown.clone(),
    )
    .await?;

    let stats_map = Array::try_from(
        enforcement_bpf
            .take_map("TELEMETRY_STATS")
            .ok_or_else(|| anyhow::anyhow!("TELEMETRY_STATS map missing from eBPF object"))?,
    )?;
    let telemetry_map = RingBuf::try_from(
        enforcement_bpf
            .take_map("TELEMETRY_RINGBUF")
            .ok_or_else(|| anyhow::anyhow!("TELEMETRY_RINGBUF map missing from eBPF object"))?,
    )?;
    let mut async_ring = AsyncFd::new(telemetry_map)?;
    let mut pipeline = TelemetryPipeline::new();
    let telemetry_stream = telemetry_stream::spawn_from_env().await;
    let _wasm_policy = WasmPolicyEngine::new();

    info!("👁️ Process visibility armed via sys_enter_execve tracepoint.");
    info!("🌐 Network visibility armed via tcp_connect kprobe.");
    info!("🔗 Lock-free correlation engine armed (DashMap PID → process name).");
    info!("📨 Correlation Kafka ingestion armed (bounded MPSC → idempotent rdkafka).");
    info!("🛡️ XDR enforcement armed. LSM bprm_check_security active blocking enabled.");
    info!(
        "⚡ Detection brain armed. RuleEngine + DataNormalizer active on ExecEvent v1 streams..."
    );
    info!(
        "📌 eBPF map pinning active under {} (PROCESS_EVENTS, RATE_LIMIT_BUCKET)",
        bpf_pin_root.display()
    );
    info!("📈 Prometheus /metrics exporter armed (default port 9090, override via NEUROMESH_METRICS_PORT)");
    info!("🩺 Health monitor armed (kernel RATE_LIMIT_DROPS + user-space channel backpressure)");
    if std::env::var("NEUROMESH_KAFKA_BROKERS").is_ok() {
        info!("📡 Kafka Slow Path armed (topic: neuromesh.telemetry.v1)");
    } else {
        info!("📡 Kafka Slow Path disabled (set NEUROMESH_KAFKA_BROKERS to enable)");
    }

    let mut stats_interval = tokio::time::interval(Duration::from_secs(5));
    stats_interval.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!(target: "neuromesh::shutdown", "shutdown token cancelled");
                break;
            }
            result = wait_for_shutdown_signal() => {
                result?;
                tracing::info!(target: "neuromesh::shutdown", "initiating graceful shutdown");
                shutdown.cancel();
                break;
            }
            _ = stats_interval.tick() => {
                log_health_metrics(&stats_map)?;
            }
            result = async_ring.async_io_mut(Interest::READABLE, |ring| {
                while let Some(item) = ring.next() {
                    let bytes = item.as_ref();
                    let Some(exec) = decode_exec_event(bytes) else {
                        continue;
                    };
                    let event = exec_event_to_security_telemetry(&exec);
                    if let Err(error) =
                        emit_pipeline_output(&mut pipeline, &telemetry_stream, &event)
                    {
                        log::warn!("telemetry pipeline failed: {error}");
                    }
                }
                Ok(())
            }) => {
                result?;
            }
            Some(visibility) = detection_rx.recv() => {
                if let Err(error) =
                    emit_pipeline_output(&mut pipeline, &telemetry_stream, &visibility)
                {
                    log::warn!("visibility pipeline failed: {error}");
                }
            }
        }
    }

    tokio::time::sleep(Duration::from_millis(SHUTDOWN_DRAIN_MS)).await;
    tracing::info!(
        target: "neuromesh::shutdown",
        drain_ms = SHUTDOWN_DRAIN_MS,
        "graceful shutdown complete — BPF links released"
    );

    Ok(())
}

/// Resolves the three struct field offsets the LSM enforcement hook needs from
/// the running kernel's BTF. Fail-closed by construction: any error returned
/// here must (and, via the `?` at the call site, does) prevent the
/// enforcement program from ever being loaded — there is no hardcoded
/// fallback value to substitute.
fn resolve_enforcement_offsets(btf: &Btf) -> Result<ResolvedOffsets, anyhow::Error> {
    let btf_bytes = btf.to_bytes();
    btf_offsets::resolve_offsets(&btf_bytes).map_err(|error| {
        anyhow::anyhow!(
            "BTF-based struct offset resolution failed — refusing to load the LSM enforcement \
             program (fail-closed): {error}"
        )
    })
}

fn emit_pipeline_output(
    pipeline: &mut TelemetryPipeline,
    telemetry_stream: &TelemetryStreamHandle,
    event: &SecurityTelemetryEvent,
) -> Result<(), anyhow::Error> {
    let output = pipeline.process(event);

    for alert in output.behavior_alerts {
        println!("{}", serde_json::to_string(&alert)?);
        telemetry_stream.try_enqueue_behavior(alert);
    }

    for alert in output.siem_alerts {
        println!("{}", RuleEngine::format_json(&alert)?);
        telemetry_stream.try_enqueue_critical(alert);
    }

    Ok(())
}

fn log_health_metrics(
    stats_map: &Array<MapData, TelemetryHealthStats>,
) -> Result<(), anyhow::Error> {
    let stats = stats_map.get(&TELEMETRY_STATS_INDEX, 0)?;
    println!(
        "📊 Telemetry Health | events_processed={} lost_events_count={}",
        stats.events_processed, stats.lost_events_count
    );
    info!(
        "📊 Telemetry Health | events_processed={} lost_events_count={}",
        stats.events_processed, stats.lost_events_count
    );
    Ok(())
}
