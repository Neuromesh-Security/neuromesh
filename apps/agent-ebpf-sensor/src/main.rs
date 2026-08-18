//! Thin orchestrator. Call order is the fail-closed bootstrap contract —
//! see `startup_sequence::ORCHESTRATOR_MAIN_CALLS`.

mod event_loop;
mod startup;
mod visibility;

use agent_ebpf_sensor::startup_sequence;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    startup::init_tracing();
    startup_sequence::log_initializing();

    let shutdown = tokio_util::sync::CancellationToken::new();
    let loaded = startup::attest_and_load_enforcement(shutdown).await?;
    let armed = startup::arm_correlator_deny_and_lsm(loaded).await?;
    let runtime = visibility::arm_visibility_and_observability(armed).await?;
    startup_sequence::emit_runtime_armed(&runtime.bpf_pin_root);
    event_loop::run(runtime).await
}
