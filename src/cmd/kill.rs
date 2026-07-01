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
            if tunnel_ours {
                proc::terminate_orphan(service.tunnel_pid.unwrap());
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
    use crate::model::ServiceKind;
    use std::path::PathBuf;

    fn svc(foreground: bool) -> Service {
        Service {
            id: 1,
            name: "x".to_string(),
            kind: ServiceKind::Static,
            dir: PathBuf::from("/tmp"),
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
}
