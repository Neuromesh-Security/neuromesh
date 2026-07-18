#![allow(linker_messages)]
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{Array, RingBuf},
    programs::LsmContext,
};
use aya_ebpf_bindings::helpers::bpf_get_current_task;
use aya_log_ebpf::info;
use neuromesh_common::{
    PathDenyEntry, CAPTURE_COMM, CAPTURE_CONTAINER_ID, CAPTURE_EUID, CAPTURE_FILENAME,
    CAPTURE_NAMESPACE_ID, CAPTURE_PPID, ENFORCEMENT_BLOCKED, EXEC_EVENT_SCHEMA_VERSION,
    EXEC_EVENT_STRUCT_SIZE, EXEC_EVENT_TYPE_EXECVE, ExecEvent, TelemetryHealthStats, MAX_COMM_LEN,
    MAX_CONTAINER_ID_LEN, MAX_FILENAME_LEN, PATH_DENY_KEY_BYTES, PATH_DENY_MAX_ENTRIES,
    TELEMETRY_STATS_INDEX, UNKNOWN_SENTINEL,
};

/// LSM denial code — maps to `-EPERM` in the kernel security hook contract.
const LSM_DENY: i32 = -1;

/// Prefix window used for deny-list matching without exhausting the 512-byte BPF stack.
/// Must equal `neuromesh_common::PATH_DENY_KEY_BYTES`.
const PATH_PREFIX_LEN: usize = PATH_DENY_KEY_BYTES;

/// `linux_binprm->filename`, `task_struct->real_parent`, and `task_struct->tgid`
/// byte offsets.
///
/// These are **not** compile-time constants: rustc/bpf-linker have no
/// equivalent of Clang's `__builtin_preserve_access_index`, so this program
/// cannot emit CO-RE relocations for these fields the way the sibling C
/// tracepoint (`src/bpf/sys_exec.bpf.c`, via `bpf_core_read()`) does.
/// Instead, the orchestrator resolves the real, running kernel's offsets from
/// its BTF at startup (see `agent_ebpf_sensor::btf_offsets`) and injects them
/// here via `aya::EbpfLoader::override_global(name, value, must_exist = true)`
/// *before* this program is loaded into the kernel.
///
/// The `u64::MAX` initializers below are never used by a correctly-functioning
/// agent: if BTF resolution fails for any reason (BTF unavailable, struct or
/// member not found by name, unexpected bitfield encoding, malformed BTF),
/// the orchestrator aborts startup and this program is never loaded — there
/// is no fallback to a guessed or previously-hardcoded offset. Per the
/// `override_global` contract, reads of these statics must go through
/// `core::ptr::read_volatile` so the compiler cannot constant-fold away the
/// load-time-patched value.
#[no_mangle]
static BPRM_FILENAME_OFFSET: u64 = u64::MAX;

#[no_mangle]
static TASK_REAL_PARENT_OFFSET: u64 = u64::MAX;

#[no_mangle]
static TASK_TGID_OFFSET: u64 = u64::MAX;

#[map]
static TELEMETRY_RINGBUF: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static TELEMETRY_STATS: Array<TelemetryHealthStats> = Array::with_max_entries(1, 0);

/// Centrally-governed path-prefix deny list (Phase 1).
///
/// Userspace bootstraps this with `/tmp/`, `/dev/shm/`, `/var/tmp/` before attach
/// and refreshes it from zt-policy-engine's `/v1/policy-bundle`. The LSM hot path
/// only performs a bounded array scan + `starts_with` — never a network call.
/// `PATH_DENY_COUNT[0]` is the active entry count (capped at PATH_DENY_MAX_ENTRIES).
#[map]
static PATH_DENY_LIST: Array<PathDenyEntry> =
    Array::with_max_entries(PATH_DENY_MAX_ENTRIES, 0);

#[map]
static PATH_DENY_COUNT: Array<u32> = Array::with_max_entries(1, 0);

#[lsm(hook = "bprm_check_security")]
pub fn neuromesh_lsm_exec_guard(ctx: LsmContext) -> i32 {
    // Decision-critical path is fail-closed (Issue #54): any error obtaining
    // the path used for deny matching must DENY, never ALLOW. Telemetry-only
    // probes (ppid / emit_blocked_exec_event) remain best-effort elsewhere.
    match try_neuromesh_lsm_exec_guard(ctx) {
        Ok(ret) => ret,
        Err(_) => LSM_DENY,
    }
}

fn try_neuromesh_lsm_exec_guard(ctx: LsmContext) -> Result<i32, i64> {
    let prefix = read_bprm_path_prefix(&ctx)?;

    if !is_blacklisted_path(&prefix) {
        return Ok(0);
    }

    emit_blocked_exec_event(&ctx);
    info!(&ctx, "Neuromesh XDR: blocked execution from blacklisted path");

    Ok(LSM_DENY)
}

fn init_exec_event(event: &mut ExecEvent, enforcement_action: u8) {
    *event = ExecEvent {
        schema_version: 0,
        event_type: EXEC_EVENT_TYPE_EXECVE,
        flags: 0,
        struct_size: EXEC_EVENT_STRUCT_SIZE,
        header_reserved: 0,
        header_pad: [0; 8],
        pid: 0,
        ppid: 0,
        tgid: 0,
        uid: 0,
        euid: 0,
        gid: 0,
        comm: [0; MAX_COMM_LEN],
        filename: [0; MAX_FILENAME_LEN],
        args_count: 0,
        container_id: [0; MAX_CONTAINER_ID_LEN],
        align_pad: [0; 4],
        namespace_id: 0,
        timestamp_ns: 0,
        enforcement_action,
        capture_status: 0,
        status_reserved: [0; 5],
    };
}

/// Returns the updated `capture_status` bitmask; callers must write it back.
/// (`capture_status` lives in a `#[repr(C, packed)]` struct, so it cannot be
/// passed as `&mut u16` — taking a reference to an unaligned field is UB.)
fn mark_unknown(bytes: &mut [u8], status: u16, bit: u16) -> u16 {
    let len = UNKNOWN_SENTINEL.len().min(bytes.len());
    bytes[..len].copy_from_slice(&UNKNOWN_SENTINEL[..len]);
    status | bit
}

fn populate_lineage(event: &mut ExecEvent) {
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;
    event.tgid = pid_tgid as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;
    event.euid = uid_gid as u32;
    event.capture_status |= CAPTURE_EUID;

    event.capture_status = mark_unknown(
        &mut event.container_id,
        event.capture_status,
        CAPTURE_CONTAINER_ID,
    );

    event.ppid = read_ppid_best_effort(event);

    if let Ok(comm) = bpf_get_current_comm() {
        let copy_len = comm.len().min(MAX_COMM_LEN);
        event.comm[..copy_len].copy_from_slice(&comm[..copy_len]);
    } else {
        event.capture_status = mark_unknown(&mut event.comm, event.capture_status, CAPTURE_COMM);
    }
}

fn read_ppid_best_effort(event: &mut ExecEvent) -> u32 {
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        if task.is_null() {
            event.capture_status |= CAPTURE_PPID;
            return 0;
        }

        let real_parent_offset = core::ptr::read_volatile(&TASK_REAL_PARENT_OFFSET) as usize;
        let parent_ptr: *const u8 =
            match bpf_probe_read_kernel(task.add(real_parent_offset) as *const *const u8) {
                Ok(ptr) => ptr,
                Err(_) => {
                    event.capture_status |= CAPTURE_PPID;
                    return 0;
                }
            };

        if parent_ptr.is_null() {
            event.capture_status |= CAPTURE_PPID;
            return 0;
        }

        let tgid_offset = core::ptr::read_volatile(&TASK_TGID_OFFSET) as usize;
        match bpf_probe_read_kernel(parent_ptr.add(tgid_offset) as *const u32) {
            Ok(ppid) => ppid,
            Err(_) => {
                event.capture_status |= CAPTURE_PPID;
                0
            }
        }
    }
}

fn read_bprm_path_prefix(ctx: &LsmContext) -> Result<[u8; PATH_PREFIX_LEN], i64> {
    let filename_ptr = read_bprm_filename_ptr(ctx)?;
    // Do not swallow probe failures into a zero-filled prefix: `[0; N]` would
    // miss every deny entry and fail-open. Propagate Err so the LSM hook denies.
    unsafe {
        bpf_probe_read_kernel(filename_ptr as *const [u8; PATH_PREFIX_LEN])
            .map_err(|error| error as i64)
    }
}

fn read_bprm_filename_ptr(ctx: &LsmContext) -> Result<*const u8, i64> {
    let bprm_ptr: *const u8 = unsafe { ctx.arg::<*const u8>(0) };
    unsafe {
        let filename_offset = core::ptr::read_volatile(&BPRM_FILENAME_OFFSET) as usize;
        bpf_probe_read_kernel(bprm_ptr.add(filename_offset) as *const *const u8)
            .map_err(|error| error as i64)
    }
}

fn emit_blocked_exec_event(ctx: &LsmContext) {
    if let Some(mut entry) = TELEMETRY_RINGBUF.reserve::<ExecEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        init_exec_event(event, ENFORCEMENT_BLOCKED);
        populate_lineage(event);
        event.filename = [0u8; MAX_FILENAME_LEN];
        if let Ok(filename_ptr) = read_bprm_filename_ptr(ctx) {
            if unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename) }
                .is_err()
            {
                event.capture_status =
                    mark_unknown(&mut event.filename, event.capture_status, CAPTURE_FILENAME);
            }
        } else {
            event.capture_status =
                mark_unknown(&mut event.filename, event.capture_status, CAPTURE_FILENAME);
        }
        event.namespace_id = 0;
        event.capture_status |= CAPTURE_NAMESPACE_ID;
        event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
        event.schema_version = EXEC_EVENT_SCHEMA_VERSION;
        entry.submit(0);
        record_event_submitted();
    } else {
        record_event_lost();
    }
}

fn is_blacklisted_path(path: &[u8]) -> bool {
    // Read the active count; treat missing/zero as "no deny entries".
    // Userspace MUST bootstrap before attach so production never hits count==0.
    let count = match PATH_DENY_COUNT.get(0) {
        Some(c) => {
            let c = *c;
            if c > PATH_DENY_MAX_ENTRIES {
                PATH_DENY_MAX_ENTRIES
            } else {
                c
            }
        }
        None => 0,
    };

    // Compile-time-bounded loop (max 64) for the BPF verifier. Early-exit when
    // i >= count so an empty/short list does not scan unused slots for matches.
    let mut i: u32 = 0;
    while i < PATH_DENY_MAX_ENTRIES {
        if i >= count {
            break;
        }
        if let Some(entry) = PATH_DENY_LIST.get(i) {
            let len = entry.len as usize;
            if len > 0 && len <= PATH_DENY_KEY_BYTES && path_starts_with(path, &entry.bytes, len) {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn path_starts_with(path: &[u8], prefix: &[u8], len: usize) -> bool {
    if path.len() < len || len == 0 || len > PATH_DENY_KEY_BYTES {
        return false;
    }
    // Bound the compare loop by PATH_DENY_KEY_BYTES (16) for the verifier.
    let mut j = 0usize;
    while j < PATH_DENY_KEY_BYTES {
        if j >= len {
            break;
        }
        if path[j] != prefix[j] {
            return false;
        }
        j += 1;
    }
    true
}

fn record_event_submitted() {
    if let Some(stats) = TELEMETRY_STATS.get_ptr_mut(TELEMETRY_STATS_INDEX) {
        unsafe {
            (*stats).events_processed = (*stats).events_processed.saturating_add(1);
        }
    }
}

fn record_event_lost() {
    if let Some(stats) = TELEMETRY_STATS.get_ptr_mut(TELEMETRY_STATS_INDEX) {
        unsafe {
            (*stats).lost_events_count = (*stats).lost_events_count.saturating_add(1);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
