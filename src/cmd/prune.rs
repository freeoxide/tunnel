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

use crate::error::Result;
use crate::model::Registry;
use crate::proc;
use crate::state::StateDir;

/// Remove stale entries (dead worker pids) and reap any orphaned cloudflared.
pub async fn run() -> Result<()> {
    let state = StateDir::new()?;

    let pruned = Registry::update(&state, |reg| {
        // Single pass so a service's fate is decided once (no TOCTOU between a
        // filter probe and a later retain probe). Stale = recorded worker that
        // is no longer alive (cmdline-checked, so PID reuse is defeated).
        let mut stale_names = Vec::new();
        let mut keep = Vec::new();
        for s in std::mem::take(&mut reg.services) {
            // Stale = recorded worker that is no longer alive. Background
            // workers use the cmdline-aware `pid_alive` (PID-reuse safe);
            // foreground services use a plain liveness probe (their `ft`
            // cmdline lacks the `run-worker` token).
            let is_stale = s.worker_pid != 0
                && if s.foreground {
                    !proc::process_exists(s.worker_pid)
                } else {
                    !proc::pid_alive(s.worker_pid)
                };
            if is_stale {
                // Best-effort reap of an orphaned cloudflared, gated on a
                // cmdline identity check so a recycled PID is never signalled
                // (mirrors kill.rs).
                if let Some(tpid) = s.tunnel_pid
                    && proc::pid_matches(tpid, "cloudflared")
                {
                    proc::terminate_orphan(tpid);
                }
                stale_names.push(s.name);
            } else {
                keep.push(s);
            }
        }
        reg.services = keep;
        stale_names
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
