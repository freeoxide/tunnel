//! The `sanitize` command: remove every dangling service, not just stale ones.
//!
//! `ft prune` reconciles the registry with the *worker* processes it records:
//! an entry whose worker died is dropped. But with `ft proxy <port>` the
//! tunnel fronts a server the OPERATOR runs, and that server can die while
//! the worker and `cloudflared` stay up. The registry then lists a
//! healthy-looking service (worker alive, URL published) whose tunnel 502s
//! every request — and prune's rule never fires, because as far as it can
//! see the worker is fine. `ft sanitize` removes ALL dangling services:
//!
//! - **Stale entries** — exactly prune's rule (see `classify` in
//!   `cmd/prune.rs`): the recorded worker no longer runs (background: the
//!   cmdline-aware `pid_alive`; foreground: `pid_matches(pid,
//!   "--foreground")` — never `Service::status`'s plain `process_exists`,
//!   which a recycled pid satisfies), or a pid-0 reservation whose
//!   `START_GRACE` expired. Fresh pid-0 reservations inside the grace
//!   window are KEPT (a start is in progress), and orphaned `cloudflared`
//!   children of stale entries are best-effort reaped, gated on a cmdline
//!   identity check.
//! - **Zombie-upstream entries** — the worker is alive and the service is
//!   Running (public URL discovered), but nothing answers on
//!   `127.0.0.1:<service.port>`. For `kind == Proxy` this is the headline
//!   case: the operator's upstream died and the tunnel 502s every request.
//!   For `kind == Static` the worker hosts the server in-process, so a live
//!   worker with a dead port is an anomaly — cleaned too, with wording that
//!   says so. A port only counts as dead after failing a DOUBLE probe
//!   (probe, wait ~750 ms, probe again), so a dev server that is mid-restart
//!   is not reaped; services still `Starting` with a live worker are left
//!   alone (their port may not be bound yet).
//!
//! Safety rules (mirroring `cmd/kill.rs`, the other command that signals
//! live workers):
//!
//! - All port probing happens BEFORE the registry lock is taken — a dead
//!   double-probe can take ~1.75 s worst case, and the lock must never be
//!   held that long. Inside `Registry::update`, each candidate is re-verified
//!   against the freshly loaded registry (same id AND same `worker_pid`)
//!   before it is removed: a concurrent `ft kill` / `ft start` may have
//!   removed the entry or recorded a different pid between the snapshot and
//!   the lock.
//! - All signalling happens OUTSIDE the lock, and only for processes
//!   confirmed ours via cmdline identity. A zombie's background worker tree
//!   is torn down with kill.rs's `TeardownKind::BackgroundGroup` semantics:
//!   `shutdown_process_group(worker_pid)` only when the worker still matches
//!   `run-worker` or its tunnel still matches `cloudflared` (cloudflared
//!   lives in the worker's group). Stale entries get prune's best-effort
//!   orphan reap, gated on `pid_matches(tpid, "cloudflared")`.
//! - A FOREGROUND service is never killed by sanitize: its worker is an
//!   `ft` process attached to the operator's own terminal, so an
//!   upstream-dead foreground service is reported as skipped ("stop it with
//!   Ctrl-C in its terminal") instead of removed. Foreground entries that
//!   are merely stale follow the stale rule exactly like prune (no live
//!   signalling is involved beyond the orphan-reap gate).

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

/// Why a zombie-upstream entry is dangling.
///
/// Split by kind because the two zombies tell different stories: a Proxy
/// fronts a port the operator owns (the server behind it dying is the
/// expected failure mode), while a Static worker IS the server, so its port
/// dying underneath a live worker contradicts the model — an anomaly.
enum ZombieReason {
    /// `kind == Proxy`: the operator's upstream server died; the tunnel 502s
    /// every request.
    UpstreamDead,
    /// `kind == Static`: the live worker should be serving the port
    /// in-process but is not.
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
                "worker is running but 127.0.0.1:{} is not answering — a static \
                 service serves that port itself, an anomaly",
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
/// rule rather than [`Service::status`]'s display-oriented one.
///
/// This is exactly the liveness half of prune's `classify` (see
/// `cmd/prune.rs`): background workers through the cmdline-aware
/// [`proc::pid_alive`]; foreground workers through
/// `pid_matches(pid, "--foreground")`, because a foreground service's worker
/// is the `ft` process itself, whose cmdline lacks the `run-worker` token.
/// [`Service::status`] cannot be used for the foreground arm: it probes with
/// plain [`proc::process_exists`] (no identity check), so a dead foreground
/// entry whose pid was recycled by an unrelated process would read Running —
/// and sanitize would then skip it forever, telling the operator to Ctrl-C a
/// process that is not the service. Returns `None` for a pid-0 reservation
/// (nothing has been recorded to probe).
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

/// Decide the fate of one service from injected inputs.
///
/// `worker_alive` is the recorded worker's liveness under prune's
/// PID-reuse-safe rule (computed by [`worker_alive`]): `None` means a pid-0
/// reservation (nothing recorded yet), `Some(false)` means the recorded pid
/// is dead or no longer ours — a recycled foreground pid lands HERE, in the
/// stale path, not in the zombie path — and `Some(true)` means a live
/// worker, which is Running when a public URL is published and still
/// Starting otherwise. `port_dead` is the origin double-probe result: `None`
/// means "not probed" (the service is not Running), `Some(true)` means both
/// probes failed. With both inputs supplied this is a pure decision table,
/// which is what makes it unit-testable without sockets or signals.
fn plan(svc: &Service, worker_alive: Option<bool>, port_dead: Option<bool>) -> Action {
    // --- rule 1: prune's staleness rule --------------------------------------
    match worker_alive {
        // The recorded worker is gone — or its pid was recycled by an
        // unrelated process: both probes behind `worker_alive` are
        // cmdline-aware, so a recycled pid reads dead here even where
        // `Service::status`'s plain `process_exists` would have shown a
        // live foreground "worker".
        Some(false) => return Action::PruneStale,
        // A pid-0 reservation: the grace split alone decides — fresh = a
        // start in progress (keep), expired = abandoned (prune). Reaping a
        // fresh one would orphan the just-spawned worker (the M1 race);
        // keeping an expired one leaves a "starting" ghost.
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
    // Reached only when Running (live worker, published URL). Only a DEAD
    // double-probe counts; an answering port — or no probe at all — keeps
    // the service.
    match port_dead {
        Some(true) if svc.foreground => Action::SkipForeground,
        Some(true) => Action::RemoveZombie {
            reason: match svc.kind {
                ServiceKind::Proxy => ZombieReason::UpstreamDead,
                ServiceKind::Static => ZombieReason::InProcessServerDead,
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
/// candidate whose entry is still the one the snapshot judged.
///
/// The re-verification is the whole point of this closure: the snapshot was
/// taken unlocked (so the slow port probes never hold the lock), and a
/// concurrent `ft kill` / `ft start` may have changed the registry in
/// between. A candidate goes only when the live registry still holds the
/// SAME id AND the SAME `worker_pid` — the identity the decision was made
/// against; anything else is left entirely alone (the concurrent writer
/// wins, and its own output stays truthful).
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
/// and — only if that failed — again after [`REPROBE_DELAY`]; only
/// still-dead counts.
///
/// A single refused connect is not proof the origin is gone: a dev server
/// restarting (watch-mode relaunch, a framework rebinding its listener)
/// drops the port for a moment and comes back, and its tunnel is perfectly
/// healthy again. Two probes ~750 ms apart ride that window out. The probes
/// reuse doctor's `origin_alive` (itself kept in sync with proxy.rs's
/// private `upstream_alive`) so no third copy of the loopback probe exists.
/// Like doctor, the blocking `std::net` connect is acceptable: this runs
/// before the registry lock is taken, with no other concurrent I/O.
async fn origin_dead_after_double_probe(port: u16) -> bool {
    if origin_alive(port) {
        return false;
    }
    tokio::time::sleep(REPROBE_DELAY).await;
    !origin_alive(port)
}

/// Remove every dangling service: stale entries (prune's rule) plus
/// zombie-upstream entries whose tunnel fronts a dead port.
///
/// The pipeline: snapshot and probe everything BEFORE the registry lock
/// (double-probes are slow), remove atomically and re-verified UNDER the
/// lock, then signal OUTSIDE it, gated on cmdline identity — see the module
/// docs for the full safety contract. Foreground services are never killed:
/// an upstream-dead foreground service is reported as left alone. Exits 0
/// whenever the command ran; only a broken environment (corrupt registry,
/// unresolvable state dir) errors through the normal Result path.
pub async fn run() -> Result<()> {
    let state = StateDir::new()?;

    // --- snapshot + probe: strictly BEFORE the registry lock -----------------
    // A dead double-probe can take ~1.75 s worst case (two 500 ms probe
    // timeouts plus the 750 ms gap; a loopback refusal is usually answered
    // instantly, so ~750 ms is typical); the lock must never be held that
    // long, so the registry is read unlocked here and every removal
    // re-verified under the lock later.
    let snapshot = Registry::load(&state)?;

    if snapshot.services.is_empty() {
        // Fresh machine: no registry at all (load falls back to an empty
        // default). Nothing was judged, so return before `Registry::update`:
        // its lock-file creation would fail against a state dir that does
        // not exist yet (the same raw-error guard `ft kill` makes with its
        // unlocked pre-read). A nothing-to-clean sanitize stays a no-op —
        // not an error, and not state creation.
        output::print_sanitized(&[], &[]);
        return Ok(());
    }

    let mut candidates = Vec::new();
    let mut skipped_foreground = Vec::new();
    for svc in &snapshot.services {
        let alive = worker_alive(svc);
        // Probe the origin only when the service is Running (worker alive
        // AND URL published): a Starting worker's port may not be bound yet,
        // and a dead worker already explains any dead port (probing it would
        // just repeat the stale finding).
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
                // gone (it normally dies via PDEATHSIG / its job object, but
                // a host reboot beats both). Gated on the `cloudflared`
                // cmdline identity, exactly like prune.
                if let Some(tpid) = svc.tunnel_pid
                    && proc::pid_matches(tpid, "cloudflared")
                {
                    proc::terminate_orphan(tpid);
                }
                bullets.push((svc.name.clone(), stale_reason(svc)));
            }
            Action::RemoveZombie { reason } => {
                // Foreground zombies were classified SkipForeground above and
                // are never removed, so a removed zombie is background by
                // construction. Assert it anyway: group-signalling a
                // foreground service would kill the operator's shell (its
                // worker shares the shell's process group).
                debug_assert!(
                    !svc.foreground,
                    "foreground zombie reached teardown — sanitize must skip it"
                );
                // kill.rs's TeardownKind::BackgroundGroup semantics: the group
                // is signalled only when at least one member is confirmed
                // ours (cmdline match) — cloudflared lives in the worker's
                // group, so shutting the group down reaches both.
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
            // Keep / SkipForeground never become candidates (filtered out of
            // `candidates` in the snapshot loop above), so they cannot reach
            // the removed list.
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
