use anyhow::{Context, Result};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf};
use std::env;

fn main() -> Result<()> {
    let path = env::args()
        .nth(1)
        .context("usage: verify-ebpf <path-to-bytecode>")?;

    println!("[ebpf-verifier] Runner kernel: {}", kernel_release());
    println!("[ebpf-verifier] Bytecode: {path}");

    let mut ebpf =
        Ebpf::load_file(&path).context("failed to parse eBPF object file")?;

    let mut verified = 0usize;

    if let Some(program) = ebpf.program_mut("neuromesh_exec_hook") {
        let program: &mut TracePoint = program.try_into()?;
        program
            .load()
            .context("kernel verifier rejected tracepoint program neuromesh_exec_hook")?;
        verified += 1;
    }

    if let Some(program) = ebpf.program_mut("neuromesh_lsm_exec_guard") {
        let program: &mut Lsm = program.try_into()?;
        let btf = Btf::from_sys_fs().context("failed to load kernel BTF (required for LSM verify)")?;
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

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}
