#![allow(linker_messages)]
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
    },
    macros::{lsm, map, tracepoint},
    maps::{Array, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use aya_log_ebpf::info;
use neuromesh_common::{
    SecurityTelemetryEvent, TelemetryHealthStats, MAX_FILENAME_LEN, TELEMETRY_STATS_INDEX,
};

/// LSM denial code — maps to `-EPERM` in the kernel security hook contract.
const LSM_DENY: i32 = -1;

/// Prefix window used for blacklist matching without exhausting the 512-byte BPF stack.
const PATH_PREFIX_LEN: usize = 16;

/// `linux_binprm->filename` field offset on kernel 6.x (see `struct linux_binprm`).
const BPRM_FILENAME_OFFSET: usize = 72;

#[map]
static TELEMETRY_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static TELEMETRY_STATS: Array<TelemetryHealthStats> = Array::with_max_entries(1, 0);

#[lsm(hook = "bprm_check_security")]
pub fn neuromesh_lsm_exec_guard(ctx: LsmContext) -> i32 {
    match try_neuromesh_lsm_exec_guard(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_neuromesh_lsm_exec_guard(ctx: LsmContext) -> Result<i32, i64> {
    let prefix = read_bprm_path_prefix(&ctx)?;

    if !is_blacklisted_path(&prefix) {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    emit_blocked_exec_event(&ctx, pid, uid);
    info!(&ctx, "Neuromesh XDR: blocked execution from blacklisted path");

    Ok(LSM_DENY)
}

#[tracepoint]
pub fn neuromesh_exec_hook(ctx: TracePointContext) -> u32 {
    match try_neuromesh_exec_hook(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_neuromesh_exec_hook(ctx: TracePointContext) -> Result<u32, i64> {
    const FILENAME_OFFSET: usize = 16;
    let filename_ptr: *const u8 = unsafe { ctx.read_at(FILENAME_OFFSET)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;

    if let Some(mut entry) = TELEMETRY_RINGBUF.reserve::<SecurityTelemetryEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.pid = pid;
        event.uid = uid;
        event.filename = [0u8; MAX_FILENAME_LEN];
        let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename) };
        entry.submit(0);
        record_event_submitted();
    } else {
        record_event_lost();
    }

    info!(&ctx, "Neuromesh Alert: Process intercepted!");
    Ok(0)
}

fn read_bprm_path_prefix(ctx: &LsmContext) -> Result<[u8; PATH_PREFIX_LEN], i64> {
    let filename_ptr = read_bprm_filename_ptr(ctx)?;
    let mut prefix = [0u8; PATH_PREFIX_LEN];
    unsafe {
        let _ = bpf_probe_read_kernel(filename_ptr as *const [u8; PATH_PREFIX_LEN]).map(|value| {
            prefix = value;
        });
    }
    Ok(prefix)
}

fn read_bprm_filename_ptr(ctx: &LsmContext) -> Result<*const u8, i64> {
    let bprm_ptr: *const u8 = unsafe { ctx.arg::<*const u8>(0) };
    unsafe {
        bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILENAME_OFFSET) as *const *const u8)
            .map_err(|error| error as i64)
    }
}

fn emit_blocked_exec_event(ctx: &LsmContext, pid: u32, uid: u32) {
    if let Some(mut entry) = TELEMETRY_RINGBUF.reserve::<SecurityTelemetryEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.pid = pid;
        event.uid = uid;
        event.filename = [0u8; MAX_FILENAME_LEN];
        if let Ok(filename_ptr) = read_bprm_filename_ptr(ctx) {
            let _ = unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename) };
        }
        entry.submit(0);
        record_event_submitted();
    } else {
        record_event_lost();
    }
}

fn is_blacklisted_path(path: &[u8]) -> bool {
    starts_with(path, b"/tmp/")
        || starts_with(path, b"/dev/shm/")
        || starts_with(path, b"/var/tmp/")
}

fn starts_with(path: &[u8], prefix: &[u8]) -> bool {
    if path.len() < prefix.len() {
        return false;
    }

    path.iter()
        .zip(prefix.iter())
        .all(|(left, right)| left == right)
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
