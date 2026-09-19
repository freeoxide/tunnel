//! The `sanitize` command: remove every dangling service, not just stale ones.
//!
//! `ft prune` reconciles the registry with the *worker* processes it records.
//! But with `ft proxy <port>` the tunnel fronts a server the OPERATOR runs,
//! and that server can die while the worker and `cloudflared` stay up — the
//! registry then lists a healthy-looking service whose tunnel 502s every
//! request, and prune's rule never fires. `ft sanitize` removes ALL dangling
//! services:
//!
//! - **Stale entries** — exactly prune's rule (see `classify` in
//!   `cmd/prune.rs`): the recorded worker no longer runs (background: the
//!   cmdline-aware `pid_alive`; foreground: `pid_matches(pid,
//!   "--foreground")` — never `Service::status`'s plain `process_exists`,
//!   which a recycled pid satisfies), or a pid-0 reservation whose
//!   `START_GRACE` expired. Fresh pid-0 reservations are KEPT, and orphaned
//!   `cloudflared` children of stale entries are best-effort reaped, gated on
//!   a cmdline identity check.
//! - **Zombie-upstream entries** — worker alive, service Running, but nothing
//!   answers on `127.0.0.1:<port>`. The headline case is `kind == Proxy`
//!   (the operator's upstream died); Static/Hook/Drop workers host the origin
//!   in-process, so a live worker with a dead port is an anomaly — cleaned
//!   too, with wording that says so. A port only counts as dead after a
//!   DOUBLE probe (probe, wait ~750 ms, probe again) so a mid-restart dev
//!   server is not reaped; still-Starting services with a live worker are
//!   left alone.
//!
//! Safety rules (mirroring `cmd/kill.rs`): all port probing happens BEFORE
//! the registry lock (a dead double-probe can take ~1.75 s); inside
//! `Registry::update` each candidate is re-verified against the freshly
//! loaded registry (same id AND same `worker_pid`) before removal, so a
//! concurrent `ft kill`/`ft start` wins; all signalling happens OUTSIDE the
//! lock and only for processes confirmed ours via cmdline identity
//! (`shutdown_process_group(worker_pid)` only when the worker still matches
//! `run-worker` or its tunnel still matches `cloudflared`; stale entries get
//! prune's orphan-reap gate). A FOREGROUND service is never killed by
//! sanitize — an upstream-dead foreground service is reported as skipped
//! ("stop it with Ctrl-C in its terminal") instead.

use std::time::Duration;

use crate::cmd::doctor::origin_alive;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::output;
use crate::proc;
use crate::state::StateDir;

/// Pause between the two origin probes of [`origin_dead_after_double_probe`].
///
/// Long enough for a restarting dev server to come back (watch-mode
/// relaunches rebind within a few hundred milliseconds), short enough that a
/// sanitize pass over one dead proxy still finishes promptly.
const REPROBE_DELAY: Duration = Duration::from_millis(750);

/// Why a zombie-upstream entry is dangling. Split by kind: a Proxy fronts a
/// port the operator owns (the upstream dying is the expected failure mode);
/// a Static/Hook/Drop worker IS the origin, so a dead port under a live
/// worker contradicts the model — an anomaly.
enum ZombieReason {
    /// `kind == Proxy`: the operator's upstream server died; the tunnel 502s
    /// every request.
    UpstreamDead,
    /// `kind == Static | Hook | Drop`: the live worker should be serving the
    /// port in-process but is not.
    InProcessServerDead,
}

impl ZombieReason {
    /// The bullet's parenthesised reason for a removed zombie.
    fn describe(&self, svc: &Service) -> String {
        match self {
            ZombieReason::UpstreamDead => format!(
                "upstream 127.0.0.1:{} is dead — tunnel was 502ing every request",
                svc.port
            ),
            ZombieReason::InProcessServerDead => format!(
                "worker is running but 127.0.0.1:{} is not answering — an ft-owned \
                 origin (static, hook, or drop) serves that port itself, an anomaly",
                svc.port
            ),
        }
    }
}

/// What sanitize decided to do with one service.
///
/// A pure decision over injected inputs (see [`plan`]); `run` performs the
/// effects, which is what makes every branch below unit-testable without
/// signals or sockets.
enum Action {
    /// Alive and healthy, or not yet judgeable — leave the entry alone.
    Keep,
    /// Dead worker or abandoned pid-0 reservation: prune's existing rule.
    PruneStale,
    /// Live worker, Running, but the origin port failed the double probe.
    RemoveZombie {
        /// Which kind of zombie this is (drives the bullet wording).
        reason: ZombieReason,
    },
    /// The zombie rule fired on a FOREGROUND service: never killed by
    /// sanitize — reported as skipped for the operator to stop by hand.
    SkipForeground,
}

/// Whether the recorded worker is still alive, under prune's PID-reuse-safe
/// rule: background through the cmdline-aware [`proc::pid_alive`], foreground
/// through `pid_matches(pid, "--foreground")` (the foreground worker is the
/// `ft` process itself, whose cmdline lacks the `run-worker` token).
/// [`Service::status`] cannot be used for the foreground arm: its plain
/// [`proc::process_exists`] is satisfied by a recycled pid, which would strand
/// the entry in SkipForeground forever. `None` = pid-0 reservation.
fn worker_alive(svc: &Service) -> Option<bool> {
    if svc.worker_pid == 0 {
        return None;
    }
    Some(if svc.foreground {
        proc::pid_matches(svc.worker_pid, "--foreground")
    } else {
        proc::pid_alive(svc.worker_pid)
    })
}

/// Decide the fate of one service from injected inputs — a pure decision
/// table, which is what makes it unit-testable without sockets or signals.
/// `worker_alive`: `None` = pid-0 reservation, `Some(false)` = dead or
/// recycled pid (stale path), `Some(true)` = live worker (Running iff a
/// public URL is published). `port_dead`: `None` = not probed, `Some(true)`
/// = both probes failed.
fn plan(svc: &Service, worker_alive: Option<bool>, port_dead: Option<bool>) -> Action {
    // --- rule 1: prune's staleness rule --------------------------------------
    match worker_alive {
        // Dead or recycled: both probes behind `worker_alive` are
        // cmdline-aware, so a recycled pid reads dead here.
        Some(false) => return Action::PruneStale,
        // A pid-0 reservation: the grace split alone decides — fresh = a
        // start in progress (keep; reaping would orphan the worker, M1),
        // expired = abandoned (prune).
        None => {
            return if svc.start_in_progress() {
                Action::Keep
            } else {
                Action::PruneStale
            };
        }
        // A live worker; which rule applies depends on the URL.
        Some(true) => {}
    }

    // Live worker whose URL has not landed yet (still Starting): the port may
    // not even be bound, so it is left alone.
    if svc.public_url.is_none() {
        return Action::Keep;
    }

    // --- rule 2: zombie upstream ---------------------------------------------
    // Reached only when Running. Only a DEAD double-probe counts; an
    // answering port — or no probe at all — keeps the service.
    match port_dead {
        Some(true) if svc.foreground => Action::SkipForeground,
        Some(true) => Action::RemoveZombie {
            reason: match svc.kind {
                // A Run service's origin is the command ft spawned: if the
                // worker+tunnel live but the port is dead, the command exited
                // — the same "upstream died" story as a proxy.
                ServiceKind::Proxy | ServiceKind::Run => ZombieReason::UpstreamDead,
                // Hook and Drop workers host their ft-owned origins
                // in-process exactly like a Static worker — the same
                // in-process anomaly.
                ServiceKind::Static | ServiceKind::Hook | ServiceKind::Drop => {
                    ZombieReason::InProcessServerDead
                }
            },
        },
        _ => Action::Keep,
    }
}

/// One snapshot entry plus the decision made against it.
struct Judgment {
    /// The entry as it was when judged; the re-verification inside [`apply`]
    /// compares the freshly loaded registry against this.
    svc: Service,
    /// The decision. Only `PruneStale` and `RemoveZombie` ever become
    /// candidates (`Keep` drops out; `SkipForeground` is reported, not
    /// removed).
    action: Action,
}

/// The bullet reason for a stale removal: a dead recorded worker and an
/// abandoned pid-0 reservation are both "stale", but they mean different
/// things to the operator reading the bullet.
fn stale_reason(svc: &Service) -> String {
    if svc.worker_pid == 0 {
        "worker pid was never recorded — the start reservation was abandoned".to_string()
    } else {
        "worker no longer running".to_string()
    }
}

/// Remove, under the registry lock held by [`Registry::update`], every
/// candidate whose entry is still the one the snapshot judged: the snapshot
/// was taken unlocked (so the slow port probes never hold the lock), so a
/// candidate goes only when the live registry still holds the SAME id AND the
/// SAME `worker_pid` — the identity the decision was made against. Anything
/// else is left alone (the concurrent writer wins).
fn apply<'a>(reg: &mut Registry, candidates: &'a [Judgment]) -> Vec<(Service, &'a Action)> {
    let mut removed = Vec::new();
    for c in candidates {
        // `position` doubles as the existence check: same id AND same
        // worker_pid, or no removal at all.
        if let Some(pos) = reg
            .services
            .iter()
            .position(|s| s.id == c.svc.id && s.worker_pid == c.svc.worker_pid)
        {
            removed.push((reg.services.remove(pos), &c.action));
        }
    }
    removed
}

/// True when `port` is dead under the DOUBLE probe: [`origin_alive`] once,
/// and — only if that failed — again after [`REPROBE_DELAY`]. A single
/// refused connect is not proof the origin is gone: a restarting dev server
/// drops the port briefly and comes back healthy; two probes ~750 ms apart
/// ride that window out. The blocking connect is fine here — it runs before
/// the registry lock, with no other concurrent I/O.
async fn origin_dead_after_double_probe(port: u16) -> bool {
    if origin_alive(port) {
        return false;
    }
    tokio::time::sleep(REPROBE_DELAY).await;
    !origin_alive(port)
}

/// Remove every dangling service: stale entries (prune's rule) plus
/// zombie-upstream entries whose tunnel fronts a dead port. Pipeline:
/// snapshot and probe BEFORE the lock, remove re-verified UNDER it, signal
/// OUTSIDE it — see the module docs for the safety contract. Exits 0
/// whenever the command ran; only a broken environment errors.
pub async fn run() -> Result<()> {
    let state = StateDir::new()?;

    // --- snapshot + probe: strictly BEFORE the registry lock -----------------
    // A dead double-probe can take ~1.75 s worst case; the lock must never
    // be held that long.
    let snapshot = Registry::load(&state)?;

    if snapshot.services.is_empty() {
        // Fresh machine: no registry at all. Return before `Registry::update`:
        // its lock-file creation would fail against a state dir that does not
        // exist yet (the same raw-error guard `ft kill` makes). A
        // nothing-to-clean sanitize stays a no-op — no error, no state
        // creation.
        output::print_sanitized(&[], &[]);
        return Ok(());
    }

    let mut candidates = Vec::new();
    let mut skipped_foreground = Vec::new();
    for svc in &snapshot.services {
        let alive = worker_alive(svc);
        // Probe the origin only when the service is Running: a Starting
        // worker's port may not be bound yet, and a dead worker already
        // explains any dead port.
        let port_dead = if let Some(true) = alive
            && svc.public_url.is_some()
        {
            Some(origin_dead_after_double_probe(svc.port).await)
        } else {
            None
        };
        let action = plan(svc, alive, port_dead);
        match action {
            Action::Keep => {}
            Action::SkipForeground => skipped_foreground.push(svc.name.clone()),
            Action::PruneStale | Action::RemoveZombie { .. } => {
                candidates.push(Judgment {
                    svc: svc.clone(),
                    action,
                });
            }
        }
    }

    // --- locked removal, re-verified against the freshly loaded registry -----
    let removed = Registry::update(&state, |reg| apply(reg, &candidates))?;

    // --- signalling + reporting: OUTSIDE the lock -----------------------------
    // Every signal below is gated on a cmdline identity check so a recycled
    // pid is never signalled (mirrors kill.rs / prune.rs).
    let mut bullets = Vec::new();
    for (svc, action) in &removed {
        match action {
            Action::PruneStale => {
                // Best-effort reap of an orphaned cloudflared whose worker is
                // gone (a host reboot beats PDEATHSIG), gated on the
                // `cloudflared` cmdline identity like prune.
                if let Some(tpid) = svc.tunnel_pid
                    && proc::pid_matches(tpid, "cloudflared")
                {
                    proc::terminate_orphan(tpid);
                }
                bullets.push((svc.name.clone(), stale_reason(svc)));
            }
            Action::RemoveZombie { reason } => {
                // Foreground zombies were classified SkipForeground above,
                // so a removed zombie is background by construction; the
                // assert guards the shell-safety invariant.
                debug_assert!(
                    !svc.foreground,
                    "foreground zombie reached teardown — sanitize must skip it"
                );
                // kill.rs's BackgroundGroup semantics: signal the group only
                // when a member is confirmed ours (cloudflared lives in the
                // worker's group, so the group kill reaches both).
                let worker_ours = proc::pid_matches(svc.worker_pid, "run-worker");
                let cloudflared_ours = svc
                    .tunnel_pid
                    .map(|p| proc::pid_matches(p, "cloudflared"))
                    .unwrap_or(false);
                if worker_ours || cloudflared_ours {
                    proc::shutdown_process_group(svc.worker_pid).await;
                }
                bullets.push((svc.name.clone(), reason.describe(svc)));
            }
            // Keep / SkipForeground never become candidates, so they cannot
            // reach the removed list.
            Action::Keep | Action::SkipForeground => {}
        }
    }

    output::print_sanitized(&bullets, &skipped_foreground);
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pure decision core.
    //!
    //! [`plan`] is a decision table over injected `(worker_alive, port_dead)`
    //! inputs and [`apply`] a pure function over a seeded registry, so every
    //! branch — the keeps, both stale prunes, both zombie kinds, the
    //! foreground skip, and the under-lock re-verification — is asserted
    //! without touching sockets or sending signals. [`worker_alive`] itself
    //! probes real /proc state, so it is pinned with the repo's standard
    //! live-self-pid trick (see prune.rs / model.rs): the test binary's own
    //! pid is alive but its cmdline lacks both `--foreground` and
    //! `run-worker`, which is exactly the recycled-pid scenario.

    use super::*;
    use chrono::TimeDelta;
    use std::path::PathBuf;

    fn service(kind: ServiceKind, foreground: bool) -> Service {
        Service {
            id: 1,
            name: "alpha".to_string(),
            kind,
            dir: (kind == ServiceKind::Static).then(|| PathBuf::from("/tmp/dir")),
            port: 3000,
            local_url: "http://127.0.0.1:3000".to_string(),
            public_url: Some("https://x.trycloudflare.com".to_string()),
            worker_pid: 123_456,
            tunnel_pid: None,
            command_pid: None,
            static_flags: Default::default(),
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground,
        }
    }

    // --- the liveness input (worker_alive) -------------------------------------

    #[test]
    fn foreground_self_pid_without_the_flag_reads_dead() {
        // prune's `foreground_self_pid_without_flag_is_stale`, mirrored:
        // this test process IS alive, but its cmdline lacks `--foreground`,
        // so the identity probe refuses to call it a live foreground worker.
        // That is the PID-reuse guard: a dead foreground entry whose pid was
        // recycled reads Some(false) here (and is pruned) instead of the
        // Running that `Service::status`'s plain `process_exists` would
        // report — which would strand the entry in SkipForeground forever.
        let mut svc = service(ServiceKind::Static, true);
        svc.worker_pid = std::process::id();
        assert_eq!(worker_alive(&svc), Some(false));
    }

    #[test]
    fn background_self_pid_without_run_worker_reads_dead() {
        // Same guard, background flavour: `pid_alive` needs the `run-worker`
        // token, which the test binary's cmdline lacks. (Background entries
        // agree with `Service::status` — it uses `pid_alive` too.)
        let mut svc = service(ServiceKind::Static, false);
        svc.worker_pid = std::process::id();
        assert_eq!(worker_alive(&svc), Some(false));
    }

    #[test]
    fn pid0_reservation_has_no_liveness_to_report() {
        let mut svc = service(ServiceKind::Proxy, false);
        svc.worker_pid = 0;
        assert_eq!(worker_alive(&svc), None);
    }

    #[test]
    fn foreground_entry_on_a_recycled_pid_is_pruned_not_skipped() {
        // The MAJOR regression this module guards against, driven through
        // the real probe feeding the pure decision: a live-but-not-ours pid
        // in a foreground slot must classify PruneStale — NOT SkipForeground,
        // where a display-grade liveness check would have stranded it while
        // telling the operator to Ctrl-C a process that is not the service.
        let mut svc = service(ServiceKind::Static, true);
        svc.worker_pid = std::process::id();
        let alive = worker_alive(&svc);
        assert!(matches!(plan(&svc, alive, Some(true)), Action::PruneStale));
    }

    // --- rule 1: prune's staleness rule ---------------------------------------

    #[test]
    fn dead_background_worker_is_pruned() {
        let svc = service(ServiceKind::Static, false);
        assert!(matches!(plan(&svc, Some(false), None), Action::PruneStale));
    }

    #[test]
    fn dead_foreground_worker_is_pruned() {
        // `Some(false)` for a foreground entry comes from the
        // `--foreground` cmdline identity probe (see `worker_alive`), so a
        // recycled pid also reads dead — foreground entries follow the stale
        // rule exactly like prune's, with no live signalling involved (only
        // the orphan-reap gate on the tunnel pid, which never touches the
        // worker).
        let svc = service(ServiceKind::Static, true);
        assert!(matches!(plan(&svc, Some(false), None), Action::PruneStale));
    }

    #[test]
    fn fresh_pid0_reservation_is_kept() {
        // created_at = now keeps the entry inside START_GRACE: the parent
        // may be mid reserve→spawn→record, and reaping now would orphan the
        // just-spawned worker (the M1 race).
        let mut svc = service(ServiceKind::Proxy, false);
        svc.worker_pid = 0;
        svc.public_url = None;
        assert!(matches!(plan(&svc, None, None), Action::Keep));
    }

    #[test]
    fn expired_pid0_reservation_is_pruned() {
        // Past the grace the pid will never land (the parent died
        // mid-start): an abandoned reservation, pruned like any stale entry
        // — with nothing to signal, which is correct, since no worker ever
        // landed.
        let mut svc = service(ServiceKind::Proxy, false);
        svc.worker_pid = 0;
        svc.public_url = None;
        svc.created_at = crate::model::now_utc()
            - (TimeDelta::from_std(crate::model::START_GRACE).expect("grace fits")
                + TimeDelta::seconds(1));
        assert!(matches!(plan(&svc, None, None), Action::PruneStale));
    }

    #[test]
    fn starting_worker_with_recorded_pid_is_kept() {
        // Live worker, URL not discovered yet: the port may not be bound —
        // left alone, and never probed by `run` in the first place.
        let mut svc = service(ServiceKind::Proxy, false);
        svc.public_url = None;
        assert!(matches!(plan(&svc, Some(true), None), Action::Keep));
    }

    // --- rule 2: zombie upstream ----------------------------------------------

    #[test]
    fn running_service_with_answering_port_is_kept() {
        let svc = service(ServiceKind::Proxy, false);
        assert!(matches!(plan(&svc, Some(true), Some(false)), Action::Keep));
    }

    #[test]
    fn running_service_without_a_probe_is_kept() {
        // Defensive: `run` passes None only for non-Running services, but a
        // missing probe must never read as evidence of a dead port.
        let svc = service(ServiceKind::Proxy, false);
        assert!(matches!(plan(&svc, Some(true), None), Action::Keep));
    }

    #[test]
    fn dead_double_probed_proxy_is_a_zombie() {
        let svc = service(ServiceKind::Proxy, false);
        assert!(matches!(
            plan(&svc, Some(true), Some(true)),
            Action::RemoveZombie {
                reason: ZombieReason::UpstreamDead
            }
        ));
    }

    #[test]
    fn zombie_proxy_reason_names_the_502ing_upstream() {
        let svc = service(ServiceKind::Proxy, false);
        assert_eq!(
            ZombieReason::UpstreamDead.describe(&svc),
            "upstream 127.0.0.1:3000 is dead — tunnel was 502ing every request"
        );
    }

    #[test]
    fn dead_double_probed_static_is_an_anomaly_zombie() {
        let svc = service(ServiceKind::Static, false);
        assert!(matches!(
            plan(&svc, Some(true), Some(true)),
            Action::RemoveZombie {
                reason: ZombieReason::InProcessServerDead
            }
        ));
    }

    #[test]
    fn zombie_static_reason_calls_out_the_anomaly() {
        let svc = service(ServiceKind::Static, false);
        let detail = ZombieReason::InProcessServerDead.describe(&svc);
        assert!(detail.contains("anomaly"), "got: {detail}");
        assert!(detail.contains("127.0.0.1:3000"), "got: {detail}");
    }

    #[test]
    fn dead_double_probed_foreground_is_skipped() {
        // The shell-safety guarantee: a foreground zombie is never removed —
        // its worker is an `ft` process attached to the operator's own
        // terminal, and group-signalling it would kill the shell.
        let svc = service(ServiceKind::Proxy, true);
        assert!(matches!(
            plan(&svc, Some(true), Some(true)),
            Action::SkipForeground
        ));
    }

    #[test]
    fn stale_reason_distinguishes_dead_worker_from_abandoned_reservation() {
        let recorded = service(ServiceKind::Static, false);
        assert_eq!(stale_reason(&recorded), "worker no longer running");
        let mut reserved = recorded;
        reserved.worker_pid = 0;
        assert_eq!(
            stale_reason(&reserved),
            "worker pid was never recorded — the start reservation was abandoned"
        );
    }

    // --- the under-lock re-verification (apply) --------------------------------

    #[test]
    fn apply_removes_a_candidate_that_still_matches() {
        let svc = service(ServiceKind::Proxy, false);
        let mut reg = Registry::default();
        reg.services.push(svc.clone());
        let candidates = [Judgment {
            svc,
            action: Action::RemoveZombie {
                reason: ZombieReason::UpstreamDead,
            },
        }];
        let removed = apply(&mut reg, &candidates);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].0.name, "alpha");
        assert!(reg.services.is_empty(), "the entry must be gone");
    }

    #[test]
    fn apply_leaves_an_entry_whose_worker_pid_changed() {
        // A concurrent `ft start` re-recorded a different worker pid between
        // the snapshot and the lock: the decision was made about the OLD
        // entry, so the NEW one must survive untouched.
        let judged = service(ServiceKind::Proxy, false);
        let mut live = judged.clone();
        live.worker_pid = 999;
        let mut reg = Registry::default();
        reg.services.push(live);
        let candidates = [Judgment {
            svc: judged.clone(),
            action: Action::RemoveZombie {
                reason: ZombieReason::UpstreamDead,
            },
        }];
        let removed = apply(&mut reg, &candidates);
        assert!(removed.is_empty(), "a changed entry must not be removed");
        assert_eq!(reg.services.len(), 1);
        assert_eq!(reg.services[0].worker_pid, 999);
    }

    #[test]
    fn apply_leaves_an_entry_that_vanished() {
        // A concurrent `ft kill` already removed it: nothing to do, and the
        // concurrent writer's outcome stands.
        let judged = service(ServiceKind::Static, false);
        let mut reg = Registry::default(); // empty
        let candidates = [Judgment {
            svc: judged,
            action: Action::PruneStale,
        }];
        let removed = apply(&mut reg, &candidates);
        assert!(removed.is_empty());
    }
}
