//! Bootstrap: attestation → BTF offsets → enforcement BPF → identity maps.
//!
//! Call order from `main.rs` is part of the fail-closed contract. Do not reorder
//! relative to `visibility` / `event_loop` without an explicit behavior change.

use agent_ebpf_sensor::btf_offsets::{self, ResolvedOffsets};
use agent_ebpf_sensor::bytecode_attestation::{self, EmbeddedArtifact};
use agent_ebpf_sensor::identity_allow::{self, IdentityAllowMaps};
use agent_ebpf_sensor::identity_correlator::{
    self, CorrelatorState, IdentityCorrelatorConfig, IdentityPolicyHooks, PeAllowlistCache,
};
use agent_ebpf_sensor::lsm_pin::{
    self, attach_and_pin_lsm_fail_closed, classify_enforcement_pins, deny_map_seed_plan,
    enforcement_pin_paths, policy_state_for_pinned_resume, DenyMapSeedPlan, EnforcementPinState,
    PINNED_ENFORCEMENT_MAPS,
};
use agent_ebpf_sensor::observability::AgentMetrics;
use agent_ebpf_sensor::path_deny::{self, PathDenyMaps, PolicySyncState};
use agent_ebpf_sensor::pin_root;
use agent_ebpf_sensor::policy_sync;
use agent_ebpf_sensor::startup_sequence;
use anyhow::Context;
use aya::maps::{Array, HashMap, MapData};
use aya::programs::links::PinnedLink;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};
use neuromesh_common::{
    PathDenyEntry, IDENTITY_ALLOW_CGROUPS_MAP, IDENTITY_EXCEPTIONS_VALID_MAP, LSM_EXEC_GUARD_PROG,
    PATH_DENY_COUNT_MAP, PATH_DENY_LIST_MAP,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

const SYS_EXEC_BPF: &[u8] = include_bytes!("../target/bpf/sys_exec.bpf.o");
const NETWORK_FILTER_BPF: &[u8] = include_bytes!("../target/bpf/network_filter.bpf.o");

pub fn sys_exec_bpf() -> &'static [u8] {
    SYS_EXEC_BPF
}

pub fn network_filter_bpf() -> &'static [u8] {
    NETWORK_FILTER_BPF
}

pub fn init_tracing() {
    // Single global logger init. `tracing-subscriber`'s default features include
    // `tracing-log`, so `fmt().init()` installs both the tracing subscriber and
    // a `log` crate bridge (LogTracer). A second `env_logger::init()` would
    // panic with SetLoggerError — do not reintroduce it.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

pub struct EnforcementLoaded {
    pub shutdown: CancellationToken,
    pub bpf_pin_root: PathBuf,
    pub enf_paths: agent_ebpf_sensor::lsm_pin::EnforcementPinPaths,
    pub btf: Btf,
    pub enforcement_bpf: Ebpf,
    pub deny_maps: PathDenyMaps,
    pub identity_maps: Arc<Mutex<IdentityAllowMaps>>,
    pub correlator_cfg: IdentityCorrelatorConfig,
    pub correlator_state: Arc<CorrelatorState>,
    pub pe_allowlist: Arc<PeAllowlistCache>,
    pub metrics: Arc<AgentMetrics>,
    pub manual_seeds: Vec<u64>,
    pub maps_preexisted: bool,
}

pub struct EnforcementArmed {
    pub shutdown: CancellationToken,
    pub bpf_pin_root: PathBuf,
    pub enforcement_bpf: Ebpf,
    pub metrics: Arc<AgentMetrics>,
    pub _lsm_link_pin: PinnedLink,
    pub _policy_sync: tokio::task::JoinHandle<()>,
    pub _correlator: Option<tokio::task::JoinHandle<()>>,
}

pub async fn attest_and_load_enforcement(
    shutdown: CancellationToken,
) -> Result<EnforcementLoaded, anyhow::Error> {
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
    startup_sequence::log_attestation_ok();

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
    startup_sequence::log_btf_offsets(
        resolved_offsets.bprm_filename_offset,
        resolved_offsets.task_real_parent_offset,
        resolved_offsets.task_tgid_offset,
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
    let deny_maps = PathDenyMaps {
        list: deny_list,
        count: deny_count,
    };

    // Slice 2a identity maps — process-lifetime only (NOT pinned). Fail-closed
    // on agent exit: exceptions die with the process; path deny survives via pins.
    let allow_cgroups = HashMap::<MapData, u64, u8>::try_from(
        enforcement_bpf
            .take_map(IDENTITY_ALLOW_CGROUPS_MAP)
            .ok_or_else(|| {
                anyhow::anyhow!("{IDENTITY_ALLOW_CGROUPS_MAP} map missing from eBPF object")
            })?,
    )?;
    let exceptions_valid = Array::<MapData, u8>::try_from(
        enforcement_bpf
            .take_map(IDENTITY_EXCEPTIONS_VALID_MAP)
            .ok_or_else(|| {
                anyhow::anyhow!("{IDENTITY_EXCEPTIONS_VALID_MAP} map missing from eBPF object")
            })?,
    )?;
    let mut identity_maps = IdentityAllowMaps {
        allow_cgroups,
        exceptions_valid,
    };
    identity_allow::set_exceptions_valid(&mut identity_maps, false)
        .context("failed to initialize ID_EXCEPT_VALID=0")?;
    let manual_seeds = identity_allow::apply_manual_cgroup_seeds_from_env(&mut identity_maps)
        .context("failed to apply NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS")?;
    if !manual_seeds.is_empty() {
        startup_sequence::log_manual_identity_seeds(manual_seeds.len());
    }

    // Shared with policy_sync + Slice 2b correlator (invalidation + auto-insert).
    let identity_maps = Arc::new(Mutex::new(identity_maps));
    let correlator_cfg = IdentityCorrelatorConfig::from_env()
        .context("invalid identity correlator configuration")?;
    let correlator_state = CorrelatorState::new();
    let pe_allowlist = Arc::new(PeAllowlistCache::new());

    // Metrics before correlator so invalidation counters are live from first event.
    let metrics = AgentMetrics::new()?;

    Ok(EnforcementLoaded {
        shutdown,
        bpf_pin_root,
        enf_paths,
        btf,
        enforcement_bpf,
        deny_maps,
        identity_maps,
        correlator_cfg,
        correlator_state,
        pe_allowlist,
        metrics,
        manual_seeds,
        maps_preexisted,
    })
}

pub async fn arm_correlator_deny_and_lsm(
    loaded: EnforcementLoaded,
) -> Result<EnforcementArmed, anyhow::Error> {
    let EnforcementLoaded {
        shutdown,
        bpf_pin_root,
        enf_paths,
        btf,
        mut enforcement_bpf,
        mut deny_maps,
        identity_maps,
        correlator_cfg,
        correlator_state,
        pe_allowlist,
        metrics,
        manual_seeds,
        maps_preexisted,
    } = loaded;

    #[cfg(target_os = "linux")]
    let (correlator_teardown_tx, correlator) = {
        if !manual_seeds.is_empty() && !correlator_cfg.enabled {
            anyhow::bail!(
                "NEUROMESH_IDENTITY_ALLOW_CGROUP_IDS is set ({} id(s) written to BPF) but \
                 NEUROMESH_IDENTITY_CORRELATOR is disabled — side table/inotify will not arm; \
                 teardown invalidation cannot run for lab seeds. Enable the correlator \
                 (NEUROMESH_IDENTITY_CORRELATOR=1) or unset the manual seed env.",
                manual_seeds.len()
            );
        }
        let spawned = identity_correlator::spawn_identity_correlator(
            correlator_cfg.clone(),
            Arc::clone(&identity_maps),
            Arc::clone(&correlator_state),
            Arc::clone(&pe_allowlist),
            Arc::clone(&metrics),
            shutdown.clone(),
        );
        if let Some((handle, teardown_tx)) = spawned {
            // Slice 2a BPF seed alone does not inform the correlator. Bridge every
            // manual seed into the side table + inotify watch (lab/2b-i test support).
            if !manual_seeds.is_empty() {
                identity_correlator::register_manual_seed_ids(
                    &correlator_state,
                    &correlator_cfg.cgroup_root,
                    &manual_seeds,
                    &teardown_tx,
                )
                .await
                .context(
                    "failed to register manual cgroup seeds with identity correlator \
                     (BPF map was seeded; side table/inotify arming failed)",
                )?;
            }
            (Some(teardown_tx), Some(handle))
        } else {
            if !manual_seeds.is_empty() {
                anyhow::bail!(
                    "manual cgroup seeds applied to BPF but identity correlator did not start — \
                     side table/inotify not armed; refusing to run with un-watched allow entries"
                );
            }
            (None, None)
        }
    };
    #[cfg(not(target_os = "linux"))]
    let correlator = {
        let _ = (&correlator_cfg, &manual_seeds);
        identity_correlator::spawn_identity_correlator(
            IdentityCorrelatorConfig {
                enabled: false,
                node_name: String::new(),
                cgroup_root: PathBuf::from("/sys/fs/cgroup"),
                trust_domain: identity_correlator::DEFAULT_SPIFFE_TRUST_DOMAIN.to_string(),
            },
            Arc::clone(&identity_maps),
            Arc::clone(&correlator_state),
            Arc::clone(&pe_allowlist),
            Arc::clone(&metrics),
            shutdown.clone(),
        );
        Option::<tokio::task::JoinHandle<()>>::None
    };

    let policy_hooks = IdentityPolicyHooks {
        allowlist: Arc::clone(&pe_allowlist),
        state: Arc::clone(&correlator_state),
        maps: Arc::clone(&identity_maps),
        #[cfg(target_os = "linux")]
        teardown_tx: correlator_teardown_tx,
        #[cfg(feature = "orchestrator")]
        metrics: Some(Arc::clone(&metrics)),
    };

    let active_count = lsm_pin::active_deny_count(&deny_maps)?;
    let seed_plan = deny_map_seed_plan(maps_preexisted, active_count)?;
    let policy_state: PolicySyncState = match seed_plan {
        DenyMapSeedPlan::Bootstrap => {
            startup_sequence::log_deny_bootstrap();
            path_deny::bootstrap_deny_maps(&mut deny_maps)
                .context("failed to bootstrap path-prefix deny list (fail-closed)")?
        }
        DenyMapSeedPlan::ResumePinned { count } => {
            startup_sequence::log_deny_resume(count);
            policy_state_for_pinned_resume()
        }
    };

    let lsm_program: &mut Lsm = enforcement_bpf
        .program_mut(LSM_EXEC_GUARD_PROG)
        .ok_or_else(|| anyhow::anyhow!("{LSM_EXEC_GUARD_PROG} program missing"))?
        .try_into()?;
    lsm_program.load("bprm_check_security", &btf)?;
    // Keep pinned link FD alive for process lifetime (pin file is the survival
    // mechanism across kill -9; holding FD is belt-and-suspenders while running).
    let _lsm_link_pin = attach_and_pin_lsm_fail_closed(lsm_program, &bpf_pin_root)?;
    startup_sequence::log_lsm_pinned(&enf_paths.link);

    let _policy_sync = policy_sync::spawn_policy_sync(
        deny_maps,
        Arc::clone(&identity_maps),
        policy_state,
        Some(policy_hooks),
        shutdown.clone(),
    );

    Ok(EnforcementArmed {
        shutdown,
        bpf_pin_root,
        enforcement_bpf,
        metrics,
        _lsm_link_pin,
        _policy_sync,
        _correlator: correlator,
    })
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
