//! Load compiled eBPF bytecode through the kernel verifier (Aya loader).
//!
//! For the Rust LSM enforcement object (`neuromesh_lsm_exec_guard`), this binary
//! also exercises the production BTF-offset resolution path: it loads the
//! runner's live `/sys/kernel/btf/vmlinux`, resolves
//! `task_struct`/`linux_binprm` field offsets via
//! [`agent_ebpf_sensor::btf_offsets`], injects them with
//! `EbpfLoader::override_global(..., must_exist = true)`, then asks the kernel
//! verifier to accept the program. Any BTF resolution failure aborts
//! (fail-closed) — matching the agent startup contract in `src/main.rs`.
//!
//! C visibility objects (tracepoint / kprobe) do not carry those globals and
//! are verified with a plain `Ebpf::load` as before.

use agent_ebpf_sensor::btf_offsets::{self, ResolvedOffsets};
use anyhow::{Context, Result};
use aya::programs::{KProbe, Lsm, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<()> {
    let path = env::args()
        .nth(1)
        .context("usage: verify-ebpf <path-to-bytecode>")?;

    println!("[ebpf-verifier] Runner kernel: {}", kernel_release());
    println!("[ebpf-verifier] Bytecode: {path}");

    let data = fs::read(Path::new(&path))
        .with_context(|| format!("failed to read eBPF object file {path}"))?;

    // Peek which programs are present so we only run BTF offset injection on
    // the enforcement object (which defines the three #[no_mangle] globals).
    // Dropping the peek releases any maps before the real load.
    let has_lsm = {
        let peek = Ebpf::load(&data).context("failed to parse eBPF object file (peek)")?;
        peek.program("neuromesh_lsm_exec_guard").is_some()
    };

    let mut ebpf = if has_lsm {
        load_enforcement_with_live_btf_offsets(&data)?
    } else {
        println!(
            "[ebpf-verifier] No neuromesh_lsm_exec_guard in object — skipping BTF offset injection"
        );
        Ebpf::load(&data).context("failed to parse eBPF object file")?
    };

    let mut verified = 0usize;

    if let Some(program) = ebpf.program_mut("neuromesh_tcp_connect") {
        let program: &mut KProbe = program.try_into()?;
        program
            .load()
            .context("kernel verifier rejected kprobe program neuromesh_tcp_connect")?;
        verified += 1;
    }

    if let Some(program) = ebpf.program_mut("neuromesh_process_events") {
        let program: &mut TracePoint = program.try_into()?;
        program
            .load()
            .context("kernel verifier rejected tracepoint program neuromesh_process_events")?;
        verified += 1;
    }

    if let Some(program) = ebpf.program_mut("neuromesh_lsm_exec_guard") {
        let program: &mut Lsm = program.try_into()?;
        let btf =
            Btf::from_sys_fs().context("failed to load kernel BTF (required for LSM verify)")?;
        program
            .load("bprm_check_security", &btf)
            .context("kernel verifier rejected LSM program neuromesh_lsm_exec_guard")?;
        verified += 1;
    }

    if verified == 0 {
        anyhow::bail!("no eBPF programs were verified");
    }

    println!("[ebpf-verifier] Verifier accepted {verified} program(s).");
    Ok(())
}

/// Resolve live-kernel offsets and load the enforcement object exactly as the
/// agent orchestrator does at startup (`src/main.rs`). Fail-closed: any BTF
/// or injection error aborts before the verifier is asked to accept the
/// program with unresolved / default (`u64::MAX`) globals.
fn load_enforcement_with_live_btf_offsets(data: &[u8]) -> Result<Ebpf> {
    let btf = Btf::from_sys_fs().context(
        "failed to load kernel BTF from /sys/kernel/btf/vmlinux — required to resolve \
         task_struct/linux_binprm field offsets; refusing to verify (fail-closed)",
    )?;
    let offsets = resolve_enforcement_offsets(&btf)?;
    println!(
        "[ebpf-verifier] BTF-resolved offsets (live kernel): \
         linux_binprm.filename={} task_struct.real_parent={} task_struct.tgid={}",
        offsets.bprm_filename_offset, offsets.task_real_parent_offset, offsets.task_tgid_offset
    );

    EbpfLoader::new()
        .override_global("BPRM_FILENAME_OFFSET", &offsets.bprm_filename_offset, true)
        .override_global(
            "TASK_REAL_PARENT_OFFSET",
            &offsets.task_real_parent_offset,
            true,
        )
        .override_global("TASK_TGID_OFFSET", &offsets.task_tgid_offset, true)
        .load(data)
        .context(
            "failed to load enforcement eBPF object with BTF-resolved offsets injected — \
             refusing to verify (fail-closed)",
        )
}

fn resolve_enforcement_offsets(btf: &Btf) -> Result<ResolvedOffsets> {
    let btf_bytes = btf.to_bytes();
    btf_offsets::resolve_offsets(&btf_bytes).map_err(|error| {
        anyhow::anyhow!(
            "BTF-based struct offset resolution failed — refusing to load the LSM enforcement \
             program (fail-closed): {error}"
        )
    })
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}
