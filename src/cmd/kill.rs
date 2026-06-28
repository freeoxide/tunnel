//! The `kill` command: stop a service and remove it from the registry.

use anyhow::bail;

use crate::error::Result;
use crate::model::Registry;
use crate::output;
use crate::proc;
use crate::state::StateDir;

/// Stop the service matching `target` and remove its registry entry.
///
/// `cloudflared` lives in the worker's process group, so signalling that group
/// reaches both. We only signal when at least one member is confirmed ours (via
/// the command-line match), so a PID or process-group that was reused by an
/// unrelated process is never signalled. The registry entry is removed and
/// saved regardless, so a stale entry is cleaned up here too.
pub async fn run(target: String) -> Result<()> {
    let state = StateDir::new()?;
    let mut registry = Registry::load(&state)?;

    let Some(service) = registry.find(&target).cloned() else {
        bail!("no service matches '{target}'");
    };

    let worker_alive = proc::pid_matches(service.worker_pid, "run-worker");
    let cloudflared_alive = service
        .tunnel_pid
        .map(|p| proc::pid_matches(p, "cloudflared"))
        .unwrap_or(false);

    // Signal the worker's whole group only when we can confirm at least one
    // member is ours. This reaps an orphaned cloudflared even when the worker
    // leader has already died (cloudflared still has the worker's pgid).
    if worker_alive || cloudflared_alive {
        if let Err(e) = proc::kill_process_group(service.worker_pid) {
            tracing::debug!(%e, "signalling worker group {} (best-effort)", service.worker_pid);
        }
    }

    registry.remove(service.id);
    registry.save(&state)?;

    if worker_alive {
        output::print_stopped(&service.name);
    } else {
        output::print_removed_stale(&service.name);
    }
    Ok(())
}
