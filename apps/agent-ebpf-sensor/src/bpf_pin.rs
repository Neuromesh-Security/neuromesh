//! BPF filesystem pinning helpers for restart-safe map persistence.

use anyhow::{Context, Result};
use aya::{Ebpf, EbpfLoader};
use std::path::{Path, PathBuf};

/// Default bpffs namespace for Neuromesh visibility maps.
pub const DEFAULT_BPF_PIN_ROOT: &str = "/sys/fs/bpf/neuromesh";

/// Maps persisted across agent restarts (rate limiter state + ringbuf backing store).
pub const PINNED_PROCESS_MAPS: &[&str] = &["PROCESS_EVENTS", "RATE_LIMIT_BUCKET"];

/// Resolve the bpffs pin root from the environment or fall back to the default namespace.
pub fn pin_root() -> PathBuf {
    std::env::var("NEUROMESH_BPF_PIN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_BPF_PIN_ROOT))
}

/// Verify that bpffs is mounted and the pin directory exists (or can be created).
pub fn prepare_pin_directory(root: &Path) -> Result<()> {
    let bpffs = Path::new("/sys/fs/bpf");
    if !bpffs.is_dir() {
        anyhow::bail!(
            "bpffs is not mounted at /sys/fs/bpf — mount the BPF filesystem before starting the agent"
        );
    }

    std::fs::create_dir_all(root).with_context(|| {
        format!(
            "failed to create BPF pin directory {} — check bpffs permissions",
            root.display()
        )
    })?;

    Ok(())
}

/// Load eBPF bytecode, reusing pinned maps when present and pinning new maps on first boot.
pub fn load_with_map_pinning(bytecode: &[u8], pin_root: &Path) -> Result<Ebpf> {
    prepare_pin_directory(pin_root)?;

    let mut reused = Vec::new();
    for map_name in PINNED_PROCESS_MAPS {
        if pin_root.join(map_name).exists() {
            reused.push(*map_name);
        }
    }

    let mut loader = EbpfLoader::new();
    for map_name in PINNED_PROCESS_MAPS {
        loader.map_pin_path(map_name, pin_root.join(map_name));
    }

    let bpf = loader
        .load(bytecode)
        .context("failed to load eBPF object with bpffs map pinning")?;

    if reused.is_empty() {
        tracing::info!(
            target: "neuromesh::bpf_pin",
            pin_root = %pin_root.display(),
            maps = ?PINNED_PROCESS_MAPS,
            "pinned eBPF maps to bpffs for restart persistence"
        );
    } else {
        tracing::info!(
            target: "neuromesh::bpf_pin",
            pin_root = %pin_root.display(),
            reused = ?reused,
            "restored pinned eBPF map state from bpffs"
        );
    }

    Ok(bpf)
}
