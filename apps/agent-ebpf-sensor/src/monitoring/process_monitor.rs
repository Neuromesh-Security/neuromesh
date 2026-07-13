//! Async RingBuf consumer for C `kprobe/sys_execve` visibility events.

use crate::monitoring::event::{ProcessEvent, ProcessEventHandler};
use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::Ebpf;
use std::ptr;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::info;

pub const PROCESS_EVENTS_MAP: &str = "PROCESS_EVENTS";
pub const SYS_EXEC_PROGRAM: &str = "kprobe_sys_execve";

/// Attach the C kprobe and spawn a Tokio task that drains `PROCESS_EVENTS`.
pub async fn start_process_monitor(bpf: &mut Ebpf) -> Result<()> {
    let program: &mut KProbe = bpf
        .program_mut(SYS_EXEC_PROGRAM)
        .with_context(|| format!("eBPF program `{SYS_EXEC_PROGRAM}` missing from object file"))?
        .try_into()
        .context("failed to cast eBPF program to KProbe")?;
    program
        .load()
        .context("kernel verifier rejected kprobe_sys_execve")?;
    program
        .attach()
        .context("failed to attach kprobe/sys_execve")?;

    let ring_buf =
        RingBuf::try_from(bpf.take_map(PROCESS_EVENTS_MAP).with_context(|| {
            format!("BPF map `{PROCESS_EVENTS_MAP}` missing from object file")
        })?)?;

    let mut async_ring = AsyncFd::new(ring_buf)?;

    tokio::spawn(async move {
        let mut handler = ProcessEventHandler::default();
        loop {
            let poll_result = async_ring
                .async_io_mut(Interest::READABLE, |ring| {
                    while let Some(item) = ring.next() {
                        let event =
                            unsafe { ptr::read_unaligned(item.as_ptr() as *const ProcessEvent) };
                        handler.observe(&event);
                    }
                    Ok(())
                })
                .await;

            if let Err(error) = poll_result {
                tracing::warn!("PROCESS_EVENTS ring buffer poll failed: {error:#}");
            }
        }
    });

    info!("Process monitor armed on kprobe/sys_execve → PROCESS_EVENTS RingBuf");
    Ok(())
}
