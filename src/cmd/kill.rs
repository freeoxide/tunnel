//! The `kill` command: stop a service and remove it from the registry.

use crate::error::Result;
use crate::model::{Registry, Service};
use crate::output;
use crate::proc;
use crate::state::StateDir;
use anyhow::bail;

/// How a service should be torn down.
///
/// Extracted as a pure function so the safety-critical rule — a FOREGROUND
/// service is never group-signalled (that would kill the operator's shell,
/// since the foreground `ft` shares its group) — can be unit-tested without
/// signalling anything.
enum TeardownKind {
    /// Foreground: signal the single `ft` pid directly.
    ForegroundDirect,
    /// Background: `SIGTERM`→grace→`SIGKILL` the worker's whole process group.
    BackgroundGroup,
}

fn teardown_kind(service: &Service) -> TeardownKind {
    if service.foreground {
        TeardownKind::ForegroundDirect
    } else {
        TeardownKind::BackgroundGroup
    }
}

/// What the locked lookup in [`run`] decided to do with the target entry.
///
/// Extracted (like [`teardown_kind`]) so the decision can be unit-tested
/// without signalling anything.
enum KillPlan {
    /// Remove the entry now and tear its process tree down (the normal path).
    Remove(Service),
    /// Leave the entry in place: its worker pid has not been recorded yet and
    /// the [`crate::model::START_GRACE`] window is still open. `run` reports
    /// a friendly "still starting" error instead of reaping.
    Starting(String),
}

/// Decide — atomically with the removal itself — whether `target` may be
/// reaped right now. `None` means no service matches.
///
/// The M1 rule: a background start reserves the entry with `worker_pid == 0`,
/// spawns the worker, and records the real pid in a second locked write.
/// Reaping the entry inside that window would orphan the just-spawned worker:
/// pid 0 never passes an identity probe, so nothing would be signalled, and
/// the worker would keep serving a tunnel no registry entry tracks. While
/// [`Service::start_in_progress`] holds, the entry is left untouched; once
/// the grace expires the reservation is abandoned (the parent died mid-start)
/// and is removed like any other entry — with nothing to signal, which is
/// correct, since no worker ever landed.
fn plan_kill(reg: &mut Registry, target: &str) -> Option<KillPlan> {
    let svc = reg.find(target)?.clone();
    if svc.start_in_progress() {
        return Some(KillPlan::Starting(svc.name));
    }
    reg.remove(svc.id);
    Some(KillPlan::Remove(svc))
}

/// Stop the service matching `target` and remove its registry entry.
///
/// - **Background** services are torn down by signalling the worker's whole
///   process group (`cloudflared` lives in that group, so it is reached too).
///   The group is only signalled when at least one member is confirmed ours
///   (cmdline match), so a PID/group reused by an unrelated process is never
///   signalled.
/// - **Foreground** services are signalled at the single `ft` pid directly —
///   NEVER the group, because the foreground `ft` shares the operator's shell's
///   process group. The pid is gated on an identity check so a recycled pid is
///   not signalled.
///
/// In both cases the registry entry is removed atomically under the lock before
/// any signalling, so even a failed signal leaves no stale entry.
///
/// Exception: an entry whose worker pid has not been recorded yet
/// (`worker_pid == 0`, inside [`crate::model::START_GRACE`]) is left in place
/// with a friendly "still starting" error — removing it mid-window would
/// orphan the just-spawned worker (M1).
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
    // lock (inside `plan_kill`) in case it vanished between the unlocked read
    // and here; the M1 guard there may instead leave the entry in place, in
    // which case the caller gets the "still starting" error rather than a
    // reaped reservation.
    let service = match Registry::update(&state, |reg| plan_kill(reg, &target))? {
        Some(KillPlan::Remove(service)) => service,
        Some(KillPlan::Starting(name)) => {
            bail!(
                "service '{name}' is still starting; try again in a few seconds once its worker pid is recorded"
            );
        }
        None => bail!("no service matches '{target}'"),
    };

    match teardown_kind(&service) {
        TeardownKind::ForegroundDirect => {
            // Signal the ft process directly (NEVER its group). Gate on an
            // identity check so a recycled pid is not signalled.
            let worker_ours = proc::pid_matches(service.worker_pid, "--foreground");
            let tunnel_ours = service
                .tunnel_pid
                .map(|p| proc::pid_matches(p, "cloudflared"))
                .unwrap_or(false);
            if worker_ours {
                proc::terminate_foreground(service.worker_pid);
            }
            // Make the data-flow invariant local and explicit: tunnel_ours can
            // only be true when tunnel_pid is Some, but bind the pid directly so
            // a future change to how tunnel_ours is computed can't panic here.
            if let Some(p) = service.tunnel_pid
                && tunnel_ours
            {
                proc::terminate_orphan(p);
            }
            if worker_ours {
                output::print_stopped(&service.name);
            } else {
                output::print_removed_stale(&service.name);
            }
        }
        TeardownKind::BackgroundGroup => {
            // `cloudflared` lives in the worker's process group, so shutting
            // that group down reaches both. Only signal when at least one
            // member is confirmed ours (cmdline match), so a PID/group reused
            // by an unrelated process is never signalled. SIGTERM → grace →
            // SIGKILL, then report the actual outcome.
            let worker_alive = proc::pid_matches(service.worker_pid, "run-worker");
            let cloudflared_alive = service
                .tunnel_pid
                .map(|p| proc::pid_matches(p, "cloudflared"))
                .unwrap_or(false);

            if worker_alive || cloudflared_alive {
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
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::START_GRACE;
    use chrono::TimeDelta;
    use std::path::PathBuf;

    fn svc(foreground: bool) -> Service {
        Service {
            id: 1,
            name: "x".to_string(),
            kind: crate::model::ServiceKind::Static,
            dir: Some(PathBuf::from("/tmp")),
            port: 1,
            local_url: "http://127.0.0.1:1".to_string(),
            public_url: None,
            worker_pid: 12345,
            tunnel_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp"),
            foreground,
        }
    }

    fn reg_with(svc: Service) -> Registry {
        let mut reg = Registry::default();
        reg.services.push(svc);
        reg
    }

    #[test]
    fn foreground_service_is_never_group_signalled() {
        // The shell-safety guarantee: a foreground service must select the
        // single-pid path, NEVER BackgroundGroup (which kills the shell).
        assert!(matches!(
            teardown_kind(&svc(true)),
            TeardownKind::ForegroundDirect
        ));
    }

    #[test]
    fn background_service_is_group_signalled() {
        assert!(matches!(
            teardown_kind(&svc(false)),
            TeardownKind::BackgroundGroup
        ));
    }

    // --- the M1 reserve→spawn→record guard -----------------------------------

    #[test]
    fn starting_entry_is_left_in_place_inside_the_grace_window() {
        // Killing a reserved-but-unrecorded entry mid-window would orphan the
        // just-spawned worker (pid 0 cannot be signalled), so the entry is
        // kept and the caller reports a friendly error instead.
        let mut s = svc(false);
        s.worker_pid = 0;
        let mut reg = reg_with(s);
        assert!(matches!(
            plan_kill(&mut reg, "x"),
            Some(KillPlan::Starting(_))
        ));
        assert_eq!(reg.services.len(), 1, "the reserved entry must survive");
    }

    #[test]
    fn abandoned_reservation_is_removed_once_grace_expires() {
        // Past the grace the pid is never landing (the parent died mid-start);
        // the entry is removed like any other, with nothing to signal.
        let mut s = svc(false);
        s.worker_pid = 0;
        s.created_at = crate::model::now_utc()
            - (TimeDelta::from_std(START_GRACE).expect("grace fits") + TimeDelta::seconds(1));
        let mut reg = reg_with(s);
        assert!(matches!(
            plan_kill(&mut reg, "x"),
            Some(KillPlan::Remove(_))
        ));
        assert!(reg.services.is_empty());
    }

    #[test]
    fn recorded_entry_is_removed_immediately() {
        // The pid already landed, so the M1 window is over — no grace applies
        // and kill proceeds regardless of the entry's age.
        let mut reg = reg_with(svc(false)); // worker_pid = 12345, created now
        assert!(matches!(
            plan_kill(&mut reg, "x"),
            Some(KillPlan::Remove(_))
        ));
        assert!(reg.services.is_empty());
    }

    #[test]
    fn unknown_target_reports_not_found() {
        let mut reg = reg_with(svc(false));
        assert!(plan_kill(&mut reg, "nope").is_none());
    }
}
