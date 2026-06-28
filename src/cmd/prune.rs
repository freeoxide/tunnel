//! The `prune` command: reconcile the registry with reality.
//!
//! After a reboot, an OOM, or a crash, the registry may still list services
//! whose worker process no longer exists (and never will again). `ft prune`
//! removes those stale entries and best-effort reaps any `cloudflared` child
//! whose recorded worker is gone (it normally dies on its own via
//! `PR_SET_PDEATHSIG`, but that does not survive a host reboot).
//!
//! Entries that are still starting (`worker_pid == 0`) are left alone — we
//! cannot distinguish "just spawned" from "orphaned mid-start", and the
//! parent's own fail-fast/timeout already cleans the latter.

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use crate::error::Result;
use crate::model::Registry;
use crate::proc;
use crate::state::StateDir;

/// Remove stale entries (dead worker pids) and reap any orphaned cloudflared.
pub async fn run() -> Result<()> {
    let state = StateDir::new()?;

    let pruned = Registry::update(&state, |reg| {
        // Collect the stale services (worker dead, not merely starting) and
        // best-effort SIGTERM any cloudflared child they leave behind.
        let stale: Vec<String> = reg
            .services
            .iter()
            .filter(|s| s.worker_pid != 0 && !proc::pid_alive(s.worker_pid))
            .inspect(|s| {
                if let Some(tpid) = s.tunnel_pid {
                    let _ = kill(Pid::from_raw(tpid as i32), Signal::SIGTERM);
                }
            })
            .map(|s| s.name.clone())
            .collect();

        // Keep starting entries (worker_pid == 0) and live entries.
        reg.services
            .retain(|s| s.worker_pid == 0 || proc::pid_alive(s.worker_pid));
        stale
    })?;

    if pruned.is_empty() {
        println!("No stale services.");
    } else {
        println!("Pruned {} stale service(s):", pruned.len());
        for name in &pruned {
            println!("  - {name}");
        }
    }
    Ok(())
}
