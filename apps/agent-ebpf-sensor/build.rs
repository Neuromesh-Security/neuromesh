use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/sys_exec.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/bpf_helpers.h");

    let out_dir = PathBuf::from("target/bpf");
    std::fs::create_dir_all(&out_dir).expect("failed to create target/bpf");

    let output = out_dir.join("sys_exec.bpf.o");
    let source = PathBuf::from("src/bpf/sys_exec.bpf.c");

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
        source.to_str().expect("source path"),
        "-o",
        output.to_str().expect("output path"),
    ]);

    if let Ok(include) = std::env::var("BPF_INCLUDE_DIR") {
        command.arg("-I").arg(include);
    }

    match command.status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            panic!(
                "clang failed to compile sys_exec.bpf.c (exit {status}); install clang and retry"
            );
        }
        Err(error) => {
            panic!("failed to invoke clang for sys_exec.bpf.c: {error}");
        }
    }

    strip_btf_ext(&output);
}

/// Aya expects `.BTF` map metadata but rejects malformed `.BTF.ext` from clang.
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
