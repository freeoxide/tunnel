//! The `kill` command: stop a service and remove it from the registry.

use anyhow::bail;

use crate::error::Result;
use crate::model::Registry;
use crate::output;
use crate::proc;
use crate::state::StateDir;

/// Stop the service matching `target` and remove its registry entry.
///
/// If the worker process is alive, its whole process group is signalled
/// (best-effort; `ESRCH` is ignored). The registry entry is removed and saved
/// regardless, so a stale entry is also cleaned up here.
pub async fn run(target: String) -> Result<()> {
    let state = StateDir::new()?;
    let mut registry = Registry::load(&state)?;

    let Some(service) = registry.find(&target).cloned() else {
        bail!("no service matches '{target}'");
    };

    let was_alive = proc::pid_alive(service.worker_pid);
    if was_alive {
        // Best-effort signal: the foundation maps nix errors to an opaque
        // io::Error, so we cannot distinguish ESRCH (already dead) from a real
        // failure. Either way we still remove the registry entry below, so a
        // transient signalling error is not fatal.
        if let Err(e) = proc::kill_process_group(service.worker_pid) {
            tracing::debug!(%e, "signalling worker {} (best-effort)", service.worker_pid);
        }
    }

    registry.remove(service.id);
    registry.save(&state)?;

    if was_alive {
        output::print_stopped(&service.name);
    } else {
        output::print_removed_stale(&service.name);
    }
    Ok(())
}
