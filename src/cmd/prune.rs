//! The `prune` command: reconcile the registry with reality — after a
//! reboot/OOM/crash, remove entries whose worker no longer exists and
//! best-effort reap an orphaned `cloudflared` (PDEATHSIG does not survive a
//! host reboot). Fresh pid-0 reservations inside START_GRACE are left alone
//! (reaping mid-window would orphan the just-spawned worker).

use crate::error::Result;
use crate::model::Registry;
use crate::proc;
use crate::state::StateDir;

/// One reconciliation pass: [`classify`] decides (pure), [`run`] performs the
/// signalling — the rules stay testable without real signals.
struct Reconciliation {
    /// Human-friendly names of the stale services, in removal order.
    stale_names: Vec<String>,
    /// Recorded `cloudflared` pids of stale services that are confirmed ours
    /// (cmdline identity check passed) and should be best-effort reaped.
    orphans_to_reap: Vec<u32>,
}

/// Decide every service's fate in one pass. Stale = recorded worker no longer
/// alive: background via cmdline-aware `pid_alive` (PID-reuse safe),
/// foreground via `pid_matches(.., "--foreground")`; a pid-0 reservation is
/// kept while START_GRACE is open. Kept set written back; stale dropped.
fn classify(reg: &mut Registry) -> Reconciliation {
    let mut keep = Vec::new();
    let mut stale_names = Vec::new();
    let mut orphans_to_reap = Vec::new();
    for s in std::mem::take(&mut reg.services) {
        let is_stale = if s.worker_pid != 0 {
            if s.foreground {
                !proc::pid_matches(s.worker_pid, "--foreground")
            } else {
                !proc::pid_alive(s.worker_pid)
            }
        } else {
            // Reserved but never recorded: kept inside the start grace
            // (reaping mid-window would orphan the worker), pruned after.
            !s.start_in_progress()
        };
        if is_stale {
            // Best-effort reap of an orphaned cloudflared, gated on cmdline
            // identity so a recycled PID is never signalled (the call is in run()).
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
    // Write the kept set back so `Registry::update` saves the reconciled
    // registry (the stale ones were consumed and never re-added).
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

    // Best-effort reap OUTSIDE the registry lock: signalling never blocks
    // other `ft` invocations and a reap failure can't roll back the prune.
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
    //! [`classify`] is pure w.r.t. signalling — the rules are asserted against
    //! a seeded registry without sending signals.

    use super::*;
    use crate::model::Service;
    use chrono::TimeDelta;
    use std::path::PathBuf;

    fn dummy_service(id: u64, name: &str) -> Service {
        Service {
            id,
            name: name.to_string(),
            kind: crate::model::ServiceKind::Static,
            dir: Some(PathBuf::from("/tmp/dir")),
            port: 1234,
            local_url: "http://127.0.0.1:1234".to_string(),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            command_pid: None,
            static_flags: Default::default(),
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
        }
    }

    /// A pid "ours" for the test: our cmdline lacks `run-worker`, so
    /// `pid_alive` reads false for it — exactly the background arm's case.
    fn live_self_pid() -> u32 {
        std::process::id()
    }

    #[test]
    fn starting_entry_worker_pid_zero_is_kept() {
        // A fresh pid-0 reservation is inside the grace window: the parent
        // may be mid reserve→spawn→record — the entry must survive.
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "starting"));
        let rec = classify(&mut reg);
        assert!(rec.stale_names.is_empty());
        assert!(rec.orphans_to_reap.is_empty());
        assert_eq!(reg.services.len(), 1);
        assert_eq!(reg.services[0].name, "starting");
    }

    #[test]
    fn abandoned_reservation_past_grace_is_pruned() {
        // Past the grace the pid will never land (parent died mid-start) —
        // prune, or it sits in `ft ls` as "starting" forever.
        let mut reg = Registry::default();
        let mut s = dummy_service(1, "leftover");
        s.created_at = crate::model::now_utc()
            - (TimeDelta::from_std(crate::model::START_GRACE).expect("grace fits")
                + TimeDelta::seconds(1));
        reg.services.push(s);
        let rec = classify(&mut reg);
        assert_eq!(rec.stale_names, vec!["leftover".to_string()]);
        assert!(rec.orphans_to_reap.is_empty());
        assert!(reg.services.is_empty());
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
    fn background_with_foreign_tunnel_pid_is_not_reaped() {
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
    fn foreground_self_pid_without_flag_is_stale() {
        // The test binary's cmdline lacks `--foreground`, so the identity
        // probe reads false — a foreign pid at a foreground slot is pruned.
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
        // keep: a second starting entry (any non-zero pid we don't own reads stale).
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
