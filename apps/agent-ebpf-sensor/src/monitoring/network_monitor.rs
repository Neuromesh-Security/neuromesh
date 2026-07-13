//! Async RingBuf consumer for C `tcp_connect` network visibility events.

use crate::monitoring::network_event::{NetworkEvent, NetworkEventHandler};
use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::Ebpf;
use std::ptr;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::info;

pub const NETWORK_EVENTS_MAP: &str = "NETWORK_EVENTS";
pub const TCP_CONNECT_PROGRAM: &str = "neuromesh_tcp_connect";

/// Attach the C kprobe and spawn a Tokio task that drains `NETWORK_EVENTS`.
pub async fn start_network_monitor(bpf: &mut Ebpf) -> Result<()> {
    let program: &mut KProbe = bpf
        .program_mut(TCP_CONNECT_PROGRAM)
        .with_context(|| format!("eBPF program `{TCP_CONNECT_PROGRAM}` missing from object file"))?
        .try_into()
        .context("failed to cast eBPF program to KProbe")?;
    program
        .load()
        .context("kernel verifier rejected neuromesh_tcp_connect kprobe")?;
    program
        .attach("tcp_connect", 0)
        .context("failed to attach tcp_connect kprobe")?;

    let ring_buf =
        RingBuf::try_from(bpf.take_map(NETWORK_EVENTS_MAP).with_context(|| {
            format!("BPF map `{NETWORK_EVENTS_MAP}` missing from object file")
        })?)?;

    let mut async_ring = AsyncFd::new(ring_buf)?;

    tokio::spawn(async move {
        let mut handler = NetworkEventHandler::default();
        loop {
            let poll_result = async_ring
                .async_io_mut(Interest::READABLE, |ring| {
                    while let Some(item) = ring.next() {
                        let event =
                            unsafe { ptr::read_unaligned(item.as_ptr() as *const NetworkEvent) };
                        handler.observe(event);
                    }
                    Ok(())
                })
                .await;

            if let Err(error) = poll_result {
                tracing::warn!("NETWORK_EVENTS ring buffer poll failed: {error:#}");
            }
        }
    });

    info!("Network monitor armed on tcp_connect → NETWORK_EVENTS RingBuf");
    Ok(())
}
