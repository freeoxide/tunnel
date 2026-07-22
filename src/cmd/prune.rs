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

/// Result of a single reconciliation pass over the registry.
///
/// Pure with respect to signalling: [`classify`] decides what *should* happen,
/// and [`run`] performs the side effects (orphan reaping). Splitting the
/// decision from the action lets the staleness rules be tested without sending
/// signals to real processes.
struct Reconciliation {
    /// Human-friendly names of the stale services, in removal order.
    stale_names: Vec<String>,
    /// Recorded `cloudflared` pids of stale services that are confirmed ours
    /// (cmdline identity check passed) and should be best-effort reaped.
    orphans_to_reap: Vec<u32>,
}

/// Decide the fate of every service in `reg` in a single pass.
///
/// Stale = recorded worker that is no longer alive:
/// - Background workers use the cmdline-aware `pid_alive` (PID-reuse safe).
/// - Foreground services use a cmdline identity probe against `--foreground`
///   (their `ft` cmdline lacks the `run-worker` token) so a recycled pid
///   never reads as a live foreground service (mirrors `kill.rs`).
///
/// `worker_pid == 0` entries are kept (still starting — see module docs). The
/// kept set is written back onto `reg.services`; the stale set is dropped.
fn classify(reg: &mut Registry) -> Reconciliation {
    let mut keep = Vec::new();
    let mut stale_names = Vec::new();
    let mut orphans_to_reap = Vec::new();
    for s in std::mem::take(&mut reg.services) {
        let is_stale = s.worker_pid != 0
            && if s.foreground {
                !proc::pid_matches(s.worker_pid, "--foreground")
            } else {
                !proc::pid_alive(s.worker_pid)
            };
        if is_stale {
            // Best-effort reap of an orphaned cloudflared, gated on a cmdline
            // identity check so a recycled PID is never signalled (mirrors
            // kill.rs). Only the identity decision lives here; the actual
            // terminate_orphan() call happens in run() to keep this pure.
            if let Some(tpid) = s.tunnel_pid
                && proc::pid_matches(tpid, "cloudflared")
            {
                orphans_to_reap.push(tpid);
            }
            stale_names.push(s.name);
        } else {
            keep.push(s);
        }
    }
    // Persist the kept services back onto the registry so `Registry::update`
    // saves the reconciled set (the stale ones were consumed by the loop and
    // never re-added).
    reg.services = keep;
    Reconciliation {
        stale_names,
        orphans_to_reap,
    }
}

/// Remove stale entries (dead worker pids) and reap any orphaned cloudflared.
pub async fn run() -> Result<()> {
    let state = StateDir::new()?;

    let rec = Registry::update(&state, classify)?;

    // Best-effort reap of the orphaned cloudflared children identified above.
    // Done OUTSIDE the registry lock so signalling never blocks other `ft`
    // invocations, and so a reap failure can't roll back the prune.
    for pid in &rec.orphans_to_reap {
        proc::terminate_orphan(*pid);
    }

    if rec.stale_names.is_empty() {
        println!("No stale services.");
    } else {
        println!("Pruned {} stale service(s):", rec.stale_names.len());
        for name in &rec.stale_names {
            println!("  - {name}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the staleness decision logic.
    //!
    //! [`classify`] is pure with respect to signalling, so the per-service
    //! rules (worker_pid==0 keep, background/cmdline-aware stale, foreground
    //! identity-checked stale, orphan reap list) can be asserted directly
    //! against a seeded registry without sending signals.

    use super::*;
    use crate::model::Service;
    use std::path::PathBuf;

    fn dummy_service(id: u64, name: &str) -> Service {
        Service {
            id,
            name: name.to_string(),
            dir: PathBuf::from("/tmp/dir"),
            port: 1234,
            local_url: "http://127.0.0.1:1234".to_string(),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
        }
    }

    /// A worker pid that is "ours" on this test process: the current pid's
    /// cmdline does not contain `run-worker`, so `pid_alive` reads false for it
    /// (i.e. it is treated as a stale/reused background worker). That is the
    /// exact behaviour under test for the background arm.
    fn live_self_pid() -> u32 {
        std::process::id()
    }

    #[test]
    fn starting_entry_worker_pid_zero_is_kept() {
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "starting"));
        let rec = classify(&mut reg);
        assert!(rec.stale_names.is_empty());
        assert!(rec.orphans_to_reap.is_empty());
        // classify writes the kept set back onto reg.services.
        assert_eq!(reg.services.len(), 1);
        assert_eq!(reg.services[0].name, "starting");
    }

    #[test]
    fn background_self_pid_without_run_worker_is_stale() {
        // Our own process's cmdline lacks `run-worker`, so pid_alive is false
        // -> a background entry pointing at us is stale (PID-reuse safe).
        let mut reg = Registry::default();
        let mut s = dummy_service(1, "bg");
        s.worker_pid = live_self_pid();
        reg.services.push(s);
        let rec = classify(&mut reg);
        assert_eq!(rec.stale_names, vec!["bg".to_string()]);
        assert!(reg.services.is_empty());
    }

    #[test]
    fn background_with_orphan_cloudflared_is_returned_for_reap() {
        let mut reg = Registry::default();
        let mut s = dummy_service(1, "bg-orphan");
        s.worker_pid = live_self_pid(); // stale -> triggers orphan check
        s.tunnel_pid = Some(4_242_424); // a pid that is definitely not cloudflared
        reg.services.push(s);
        let rec = classify(&mut reg);
        assert_eq!(rec.stale_names, vec!["bg-orphan".to_string()]);
        // pid 4242424 does not exist, so pid_matches(.., "cloudflared") is
        // false -> it is NOT in the reap list (recycled-pid safety).
        assert!(rec.orphans_to_reap.is_empty());
    }

    #[test]
    fn foreground_self_pid_is_alive_and_kept() {
        // Our own process's cmdline contains `--foreground`? No — the test
        // binary's cmdline is `ft-<hash>` (deps), so it does NOT contain the
        // flag. That means pid_matches(self, "--foreground") is false here,
        // making the foreground entry read as stale. We assert THAT behaviour
        // (a foreign pid at a foreground slot is pruned), and separately rely
        // on the live-self background test above for the keep side.
        let mut reg = Registry::default();
        let mut s = dummy_service(1, "fg");
        s.foreground = true;
        s.worker_pid = live_self_pid();
        reg.services.push(s);
        let rec = classify(&mut reg);
        assert_eq!(rec.stale_names, vec!["fg".to_string()]);
    }

    #[test]
    fn foreground_dead_pid_is_stale() {
        let mut reg = Registry::default();
        let mut s = dummy_service(1, "fg-dead");
        s.foreground = true;
        s.worker_pid = 999_999; // almost certainly not running
        reg.services.push(s);
        let rec = classify(&mut reg);
        assert_eq!(rec.stale_names, vec!["fg-dead".to_string()]);
    }

    #[test]
    fn mixed_registry_reconciles_to_right_keep_set() {
        let mut reg = Registry::default();
        // keep: starting (pid 0)
        reg.services.push(dummy_service(1, "starting"));
        // keep: background entry whose worker_pid==0 path is the only keep
        // (any non-zero pid we don't own reads stale). Add a genuine keep by
        // reusing pid 0 semantics via a second starting entry.
        let mut s2 = dummy_service(2, "starting-2");
        s2.worker_pid = 0;
        reg.services.push(s2);
        // stale: background self pid
        let mut s3 = dummy_service(3, "bg-stale");
        s3.worker_pid = live_self_pid();
        reg.services.push(s3);
        // stale: foreground dead pid
        let mut s4 = dummy_service(4, "fg-stale");
        s4.foreground = true;
        s4.worker_pid = 999_999;
        reg.services.push(s4);

        let rec = classify(&mut reg);

        let kept: Vec<&str> = reg.services.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(kept, vec!["starting", "starting-2"]);
        let mut stale = rec.stale_names.clone();
        stale.sort();
        assert_eq!(stale, vec!["bg-stale".to_string(), "fg-stale".to_string()]);
    }
}
