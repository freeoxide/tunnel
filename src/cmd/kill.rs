//! The `kill` command: stop a service and remove it from the registry.

use anyhow::bail;

use crate::error::Result;
use crate::model::Registry;
use crate::output;
use crate::proc;
use crate::state::StateDir;

/// Stop the service matching `target` and remove its registry entry.
///
/// `cloudflared` lives in the worker's process group, so shutting that group
/// down reaches both. We only signal when at least one member is confirmed ours
/// (via the command-line match), so a PID or process-group reused by an
/// unrelated process is never signalled. The group is `SIGTERM`'d, given a
/// grace window, then `SIGKILL`'d to guarantee cleanup, and the result is
/// reported accurately.
pub async fn run(target: String) -> Result<()> {
    let state = StateDir::new()?;

    // Find and remove the entry atomically under the registry lock so a
    // concurrent writer cannot resurrect or duplicate it.
    let service = Registry::update(&state, |reg| reg.find(&target).cloned().map(|svc| {
        reg.remove(svc.id);
        svc
    }))?;

    let Some(service) = service else {
        bail!("no service matches '{target}'");
    };

    let worker_alive = proc::pid_matches(service.worker_pid, "run-worker");
    let cloudflared_alive = service
        .tunnel_pid
        .map(|p| proc::pid_matches(p, "cloudflared"))
        .unwrap_or(false);

    if worker_alive || cloudflared_alive {
        // SIGTERM → grace → SIGKILL on the worker's whole group.
        proc::shutdown_process_group(service.worker_pid);
    }

    // Re-probe so the user-facing message reflects the actual outcome.
    let still_worker = proc::pid_matches(service.worker_pid, "run-worker");
    let still_cloudflared = service
        .tunnel_pid
        .map(|p| proc::pid_matches(p, "cloudflared"))
        .unwrap_or(false);

    if worker_alive {
        if still_worker || still_cloudflared {
            println!(
                "Sent kill signal to {} (a process may still be exiting).",
                service.name
            );
        } else {
            output::print_stopped(&service.name);
        }
    } else {
        output::print_removed_stale(&service.name);
    }
    Ok(())
}
