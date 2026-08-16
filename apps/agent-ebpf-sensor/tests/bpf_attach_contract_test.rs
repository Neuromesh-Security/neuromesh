//! Attach-contract guards for the C process-visibility object (Issue #126).
//!
//! The kernel programs in `src/bpf/sys_exec.bpf.c` cannot be exercised offline —
//! they need a live kernel, so CI proves them via `verify_ebpf` (verifier) and the
//! droplet scripts (behaviour). What *can* regress silently in a pure refactor is
//! the wiring: an attach being dropped, or the `execveat` argument indices being
//! copied from `execve`.
//!
//! `sys_enter_execve(pathname, argv, envp)` puts pathname at `args[0]`, but
//! `sys_enter_execveat(dfd, pathname, argv, envp, flags)` shifts it to `args[1]`
//! because `dfd` takes the first slot. Reusing the execve indices compiles, passes
//! the verifier, and attaches successfully — it just reads a file descriptor as a
//! pointer and produces silent garbage. These assertions pin that contract.

const SYS_EXEC_BPF_SOURCE: &str = include_str!("../src/bpf/sys_exec.bpf.c");
const EXEC_EVENT_HEADER: &str = include_str!("../src/bpf/exec_event.h");

/// Collapse all runs of whitespace to single spaces so these assertions describe
/// the code's contract rather than its formatting.
fn normalized(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalized_source() -> String {
    normalized(SYS_EXEC_BPF_SOURCE)
}

#[test]
fn both_exec_syscall_tracepoints_are_attached() {
    for section in [
        r#"SEC("tracepoint/syscalls/sys_enter_execve")"#,
        r#"SEC("tracepoint/syscalls/sys_enter_execveat")"#,
    ] {
        assert!(
            SYS_EXEC_BPF_SOURCE.contains(section),
            "sys_exec.bpf.c must declare {section} — exec visibility parity with LSM \
             enforcement depends on both attaches (Issue #126)"
        );
    }
}

#[test]
fn program_names_match_the_shared_object_name_constants() {
    for name in [
        neuromesh_common::PROCESS_EVENTS_PROG,
        neuromesh_common::PROCESS_EVENTS_AT_PROG,
    ] {
        assert!(
            SYS_EXEC_BPF_SOURCE.contains(&format!("int {name}(")),
            "sys_exec.bpf.c must define program `{name}`; the loader resolves it by \
             this exact name and a mismatch fails only at runtime"
        );
        assert!(
            name.len() <= neuromesh_common::BPF_OBJ_NAME_MAX,
            "`{name}` exceeds BPF_OBJ_NAME_MAX and would be truncated by the kernel"
        );
    }
}

/// `dfd` occupies `args[0]` for execveat, shifting pathname to `args[1]` and argv
/// to `args[2]`. Reading the execve indices here would silently treat an fd as a
/// userspace pointer.
#[test]
fn execveat_reads_the_shifted_tracepoint_arguments() {
    let source = normalized_source();

    assert!(
        source.contains("(const char __user *)trace->args[1], (const char __user *const __user *)trace->args[2], EXEC_FLAG_SYSCALL_EXECVEAT"),
        "nm_execveat must read pathname from args[1] and argv from args[2] (dfd is args[0])"
    );
    assert!(
        source.contains(
            "(const char __user *)trace->args[0], (const char __user *const __user *)trace->args[1], 0"
        ),
        "nm_proc_events must keep reading pathname from args[0] and argv from args[1]"
    );
}

/// The variant is a `flags` bit rather than a new `event_type` because userspace
/// `ExecEvent::is_valid()` hard-requires `event_type == EXEC_EVENT_TYPE_EXECVE`.
/// Keeping it in `flags` also holds `struct_size` at 668 so every field offset and
/// the C `_Static_assert` stay valid.
#[test]
fn syscall_variant_flags_agree_between_c_header_and_rust_mirror() {
    let header = normalized(EXEC_EVENT_HEADER);

    assert!(
        header.contains("#define EXEC_FLAG_SYSCALL_EXECVEAT (1U << 0)"),
        "C header must define EXEC_FLAG_SYSCALL_EXECVEAT as bit 0"
    );
    assert!(
        header.contains("#define EXEC_FLAG_PATH_FROM_FD (1U << 1)"),
        "C header must define EXEC_FLAG_PATH_FROM_FD as bit 1"
    );
    assert_eq!(neuromesh_common::EXEC_FLAG_SYSCALL_EXECVEAT, 1 << 0);
    assert_eq!(neuromesh_common::EXEC_FLAG_PATH_FROM_FD, 1 << 1);

    assert!(
        header.contains("#define EXEC_EVENT_STRUCT_SIZE 668U"),
        "adding the syscall-variant flag must not change ExecEvent's size"
    );
    assert_eq!(neuromesh_common::EXEC_EVENT_STRUCT_SIZE, 668);
}

/// Both tracepoints must go through the same rate limiter, otherwise the added
/// attach would raise the aggregate admitted rate above the ~500k EPS ceiling the
/// 1 MiB `PROCESS_EVENTS` RingBuf was sized against.
#[test]
fn exec_tracepoints_share_one_rate_limiter_and_ringbuf() {
    let source = normalized_source();

    // The definition reads `rate_limit_allow(void)`, so this counts call sites only.
    assert_eq!(
        source.matches("rate_limit_allow()").count(),
        1,
        "expected a single rate_limit_allow() call in the shared emit path — a \
         per-program limiter would double the admitted event rate"
    );
    assert_eq!(
        source
            .matches("bpf_ringbuf_reserve(&PROCESS_EVENTS")
            .count(),
        1,
        "both tracepoints must reserve from the single shared PROCESS_EVENTS RingBuf"
    );
    assert!(
        source.contains("__uint(max_entries, 1024 * 1024); } PROCESS_EVENTS SEC(\".maps\")"),
        "PROCESS_EVENTS must remain a 1 MiB RingBuf"
    );
}
