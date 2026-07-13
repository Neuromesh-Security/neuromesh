//! High-throughput async consumer for `PROCESS_EVENTS` RingBuf telemetry.

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use std::ffi::CStr;
use std::ptr;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::info;

pub const PROCESS_EVENTS_MAP: &str = "PROCESS_EVENTS";
pub const SYS_EXEC_PROGRAM: &str = "neuromesh_sys_enter_execve";

/// Kernel/userspace shared layout for `sys_enter_execve` visibility events.
///
/// Memory layout (little-endian, `#[repr(C)]`, 168 bytes total):
/// ```text
/// +0x00  pid      u32
/// +0x04  uid      u32
/// +0x08  ppid     u32
/// +0x0C  comm     [u8; 16]
/// +0x1C  filename [u8; 128]
/// Total: 156 bytes
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessEvent {
    pub pid: u32,
    pub uid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 128],
}

unsafe impl aya::Pod for ProcessEvent {}

/// Attach the C `sys_enter_execve` tracepoint and spawn a Tokio polling task.
pub async fn start_process_monitor(bpf: &mut Ebpf) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(SYS_EXEC_PROGRAM)
        .with_context(|| format!("eBPF program `{SYS_EXEC_PROGRAM}` missing from object file"))?
        .try_into()
        .context("failed to cast eBPF program to TracePoint")?;
    program
        .load()
        .context("kernel verifier rejected sys_enter_execve tracepoint")?;
    program
        .attach("syscalls", "sys_enter_execve")
        .context("failed to attach sys_enter_execve tracepoint")?;

    let ring_buf = RingBuf::try_from(
        bpf.take_map(PROCESS_EVENTS_MAP)
            .with_context(|| format!("BPF map `{PROCESS_EVENTS_MAP}` missing from object file"))?,
    )?;

    let mut async_ring = AsyncFd::new(ring_buf)?;

    tokio::spawn(async move {
        loop {
            let poll_result = async_ring
                .async_io_mut(Interest::READABLE, |ring| {
                    while let Some(item) = ring.next() {
                        let event = unsafe {
                            ptr::read_unaligned(item.as_ptr() as *const ProcessEvent)
                        };
                        log_process_event(&event);
                    }
                    Ok(())
                })
                .await;

            if let Err(error) = poll_result {
                tracing::warn!("PROCESS_EVENTS ring buffer poll failed: {error:#}");
            }
        }
    });

    info!("Process monitor armed on sys_enter_execve → PROCESS_EVENTS RingBuf");
    Ok(())
}

fn log_process_event(event: &ProcessEvent) {
    let comm = cstr_field(&event.comm);
    let filename = cstr_field(&event.filename);
    info!(
        pid = event.pid,
        uid = event.uid,
        ppid = event.ppid,
        comm = comm,
        file = filename,
        "Process Executed: PID={} UID={} PPID={} COMM={} File={}",
        event.pid,
        event.uid,
        event.ppid,
        comm,
        filename
    );
}

fn cstr_field(bytes: &[u8]) -> &str {
    CStr::from_bytes_until_nul(bytes)
        .ok()
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<invalid>")
}

#[cfg(test)]
mod tests {
    use super::ProcessEvent;

    #[test]
    fn process_event_layout_matches_bpf_struct() {
        assert_eq!(core::mem::size_of::<ProcessEvent>(), 156);
        assert_eq!(core::mem::offset_of!(ProcessEvent, comm), 12);
        assert_eq!(core::mem::offset_of!(ProcessEvent, filename), 28);
    }
}
