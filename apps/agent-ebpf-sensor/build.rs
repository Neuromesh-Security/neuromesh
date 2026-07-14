use std::path::{Path, PathBuf};
use std::process::Command;

const BPF_SOURCES: &[(&str, &str)] = &[
    ("src/bpf/sys_exec.bpf.c", "target/bpf/sys_exec.bpf.o"),
    (
        "src/bpf/network_filter.bpf.c",
        "target/bpf/network_filter.bpf.o",
    ),
];

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/sys_exec.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/network_filter.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/bpf_helpers.h");
    println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");
    println!("cargo:rerun-if-changed=src/bpf/bpf/bpf_tracing.h");

    let out_dir = PathBuf::from("target/bpf");
    std::fs::create_dir_all(&out_dir).expect("failed to create target/bpf");

    for (source, output) in BPF_SOURCES {
        compile_bpf(source, output);
    }

    if std::env::var("CARGO_FEATURE_ORCHESTRATOR").is_ok() {
        configure_enforcement_bytecode();
    }
}

/// Resolve Ring 0 enforcement bytecode for `include_bytes!` in the orchestrator binary.
fn configure_enforcement_bytecode() {
    let default = PathBuf::from("ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf");
    let path = std::env::var("NEUROMESH_EBPF_ENFORCEMENT_BYTECODE")
        .map(PathBuf::from)
        .unwrap_or(default);

    let abs = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .expect("current dir")
            .join(path)
    };

    println!("cargo:rerun-if-env-changed=NEUROMESH_EBPF_ENFORCEMENT_BYTECODE");
    println!(
        "cargo:rerun-if-changed=ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf"
    );

    if !abs.is_file() {
        panic!(
            "eBPF enforcement bytecode not found at {}. \
             Build apps/agent-ebpf-sensor/ebpf first or set NEUROMESH_EBPF_ENFORCEMENT_BYTECODE.",
            abs.display()
        );
    }

    println!(
        "cargo:rustc-env=NEUROMESH_EBPF_ENFORCEMENT_BYTECODE={}",
        abs.display()
    );
}

fn compile_bpf(source: &str, output: &str) {
    let output_path = PathBuf::from(output);
    let source_path = PathBuf::from(source);

    let mut command = Command::new("clang");
    command.args([
        "-g",
        "-O2",
        "-target",
        "bpf",
        "-D__TARGET_ARCH_x86",
        "-I",
        "src/bpf",
        "-c",
        source_path.to_str().expect("source path"),
        "-o",
        output_path.to_str().expect("output path"),
    ]);

    if let Ok(include) = std::env::var("BPF_INCLUDE_DIR") {
        command.arg("-I").arg(include);
    }

    match command.status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            panic!(
                "clang failed to compile {} (exit {status}); install clang and retry",
                source_path.display()
            );
        }
        Err(error) => {
            panic!(
                "failed to invoke clang for {}: {error}",
                source_path.display()
            );
        }
    }

    strip_btf_ext(&output_path);
}

/// Clang emits `.BTF.ext` alongside `.BTF`; Aya requires the former to be removed.
fn strip_btf_ext(object: &Path) {
    for tool in [
        "llvm-objcopy",
        "llvm-objcopy-18",
        "llvm-objcopy-17",
        "llvm-objcopy-16",
    ] {
        match Command::new(tool)
            .args([
                "--remove-section=.BTF.ext",
                object.to_str().expect("object path"),
            ])
            .status()
        {
            Ok(status) if status.success() => return,
            _ => continue,
        }
    }

    panic!(
        "llvm-objcopy is required to strip .BTF.ext from {}; install llvm and retry",
        object.display()
    );
}
