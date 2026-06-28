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

    // Resolve `target` with an UNLOCKED read first. This avoids creating
    // `registry.lock` (which would fail with a raw 'No such file or directory'
    // when the state dir does not yet exist) on a system with no services, and
    // lets us emit the friendly 'no service matches' message without any dir.
    let exists = Registry::load(&state)?.find(&target).is_some();
    if !exists {
        bail!("no service matches '{target}'");
    }

    // Remove the entry atomically under the registry lock so a concurrent
    // writer cannot resurrect or duplicate it. `find` is re-checked under the
    // lock in case it vanished between the unlocked read and here; `update`
    // returns the removed service (cloned) or an error if the dir disappeared.
    let Some(service) = Registry::update(&state, |reg| {
        reg.find(&target).cloned().inspect(|svc| {
            reg.remove(svc.id);
        })
    })?
    else {
        bail!("no service matches '{target}'");
    };

    let worker_alive = proc::pid_matches(service.worker_pid, "run-worker");
    let cloudflared_alive = service
        .tunnel_pid
        .map(|p| proc::pid_matches(p, "cloudflared"))
        .unwrap_or(false);

    if worker_alive || cloudflared_alive {
        // SIGTERM → grace → SIGKILL on the worker's whole group.
        proc::shutdown_process_group(service.worker_pid).await;
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
