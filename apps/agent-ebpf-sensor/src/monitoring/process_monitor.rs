//! Async RingBuf consumer for C `sys_enter_execve` visibility events.

use crate::monitoring::correlation::CorrelationEngine;
use crate::monitoring::event::{ProcessEvent, ProcessEventHandler};
use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::Ebpf;
use std::ptr;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::info;

pub const PROCESS_EVENTS_MAP: &str = "PROCESS_EVENTS";
pub const SYS_EXEC_PROGRAM: &str = "neuromesh_process_events";

/// Attach the C tracepoint and spawn a Tokio task that drains `PROCESS_EVENTS`.
pub async fn start_process_monitor(
    bpf: &mut Ebpf,
    correlation: Arc<CorrelationEngine>,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(SYS_EXEC_PROGRAM)
        .with_context(|| format!("eBPF program `{SYS_EXEC_PROGRAM}` missing from object file"))?
        .try_into()
        .context("failed to cast eBPF program to TracePoint")?;
    program
        .load()
        .context("kernel verifier rejected neuromesh_process_events tracepoint")?;
    program
        .attach("syscalls", "sys_enter_execve")
        .context("failed to attach sys_enter_execve tracepoint")?;

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
                        let pid = event.pid;
                        correlation.register_process(pid, &event.filename);
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

    info!("Process monitor armed on sys_enter_execve → PROCESS_EVENTS RingBuf");
    Ok(())
}
