//! The `sanitize` command: remove every dangling service, not just stale ones.
//!
//! Beyond prune's staleness rule (dead/recycled worker, expired pid-0
//! reservation), sanitize removes zombie-upstream entries: worker alive and
//! Running but nothing answers on `127.0.0.1:<port>` (the operator's upstream
//! died; the tunnel 502s every request). A port counts as dead only after a
//! DOUBLE probe ~750 ms apart, so a mid-restart dev server is not reaped.
//!
//! Safety rules (mirroring `cmd/kill.rs`): port probes run BEFORE the
//! registry lock; each candidate is re-verified under it (same id AND
//! `worker_pid`) so a concurrent writer wins; signalling runs OUTSIDE the
//! lock, gated on cmdline identity. A FOREGROUND service is never killed.

use std::time::Duration;

use crate::cmd::doctor::origin_alive_async;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::output;
use crate::proc;
use crate::state::StateDir;

/// Pause between the two origin probes: long enough for a restarting dev
/// server to rebind, short enough to keep a dead-proxy pass prompt.
const REPROBE_DELAY: Duration = Duration::from_millis(750);

/// Why a zombie-upstream entry is dangling: a Proxy fronts an operator-owned
/// port; a Static/Hook/Drop worker IS the origin, so a dead port is an anomaly.
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

/// What sanitize decided for one service — a pure decision over injected
/// inputs ([`plan`]); `run` performs the effects.
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

/// Worker liveness, PID-reuse-safe: background via the cmdline-aware
/// [`proc::pid_alive`], foreground via `pid_matches(pid, "--foreground")` —
/// NOT [`Service::status`], whose plain `process_exists` a recycled pid
/// satisfies. `None` = pid-0 reservation.
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

/// The fate of one service, pure over injected inputs. `worker_alive`:
/// `None` = pid-0 reservation, `Some(false)` = dead/recycled, `Some(true)`
/// = live; `port_dead`: `None` = not probed, `Some(true)` = both failed.
fn plan(svc: &Service, worker_alive: Option<bool>, port_dead: Option<bool>) -> Action {
    // --- rule 1: prune's staleness rule --------------------------------------
    match worker_alive {
        Some(false) => return Action::PruneStale,
        // A pid-0 reservation: fresh = a start in progress (reaping would
        // orphan the worker), expired = abandoned.
        None => {
            return if svc.start_in_progress() {
                Action::Keep
            } else {
                Action::PruneStale
            };
        }
        Some(true) => {}
    }

    // Live worker whose URL has not landed yet (still Starting): the port may
    // not even be bound, so it is left alone.
    if svc.public_url.is_none() {
        return Action::Keep;
    }

    // --- rule 2: zombie upstream ---------------------------------------------
    // Reached only when Running; only a DEAD double-probe counts.
    match port_dead {
        Some(true) if svc.foreground => Action::SkipForeground,
        Some(true) => Action::RemoveZombie {
            reason: match svc.kind {
                // A Run's origin is the command ft spawned — same story.
                ServiceKind::Proxy | ServiceKind::Run => ZombieReason::UpstreamDead,
                // Hook/Drop host in-process like Static — the same anomaly.
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
    /// The decision; only PruneStale/RemoveZombie become candidates (Keep
    /// drops out; SkipForeground is reported, not removed).
    action: Action,
}

/// Bullet reason for a stale removal — dead worker vs abandoned reservation.
fn stale_reason(svc: &Service) -> String {
    if svc.worker_pid == 0 {
        "worker pid was never recorded — the start reservation was abandoned".to_string()
    } else {
        "worker no longer running".to_string()
    }
}

/// Remove, under the lock, every candidate still identical to what the
/// (unlocked, slow-probe) snapshot judged — same id AND `worker_pid`.
fn apply<'a>(reg: &mut Registry, candidates: &'a [Judgment]) -> Vec<(Service, &'a Action)> {
    let mut removed = Vec::new();
    for c in candidates {
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

/// [`origin_alive_async`] once, and only if that failed again after
/// [`REPROBE_DELAY`] — a restarting dev server drops the port briefly.
async fn origin_dead_after_double_probe(port: u16) -> bool {
    if origin_alive_async(port).await {
        return false;
    }
    tokio::time::sleep(REPROBE_DELAY).await;
    !origin_alive_async(port).await
}

/// Judge every snapshot entry — worker liveness (a fast /proc read), the
/// origin double-probes, and [`plan`] — returning removal candidates plus
/// the skipped-foreground names. The probes are spawned per service and
/// awaited together: N dead origins pay ONE [`REPROBE_DELAY`] gap, not N;
/// the gap itself is the deliberate mid-restart tolerance — overlapped,
/// never shortened. A wall-clock test pins this exact loop: re-serializing
/// it must fail CI, not just the wall-clock harness.
async fn judge(services: &[Service]) -> (Vec<Judgment>, Vec<String>) {
    let mut liveness = Vec::with_capacity(services.len());
    let mut probes = Vec::with_capacity(services.len());
    for svc in services {
        let alive = worker_alive(svc);
        // Probe the origin only when Running: a Starting worker's port may
        // not be bound yet; a dead worker already explains a dead port.
        let probe = (alive == Some(true) && svc.public_url.is_some())
            .then(|| tokio::spawn(origin_dead_after_double_probe(svc.port)));
        liveness.push(alive);
        probes.push(probe);
    }

    let mut candidates = Vec::new();
    let mut skipped_foreground = Vec::new();
    for ((svc, alive), probe) in services.iter().zip(liveness).zip(probes) {
        // A probe task fails only by panicking; reading that as not-dead
        // keeps a failed probe from ever removing an entry.
        let port_dead = match probe {
            Some(handle) => Some(handle.await.unwrap_or(false)),
            None => None,
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
    (candidates, skipped_foreground)
}

/// Remove every dangling service (stale + zombie-upstream); see the module
/// docs for the probe/re-verify/signal safety contract. Exits 0 whenever it ran.
pub async fn run() -> Result<()> {
    let state = StateDir::new()?;

    // --- snapshot + probe: strictly BEFORE the registry lock -----------------
    // A dead double-probe can take ~1.75 s; never hold the lock that long.
    let snapshot = Registry::load(&state)?;

    if snapshot.services.is_empty() {
        // Fresh machine: return before `Registry::update` — its lock-file
        // creation would fail on a not-yet-existing state dir; stay a no-op.
        output::print_sanitized(&[], &[]);
        return Ok(());
    }

    let (candidates, skipped_foreground) = judge(&snapshot.services).await;

    // --- locked removal, re-verified against the freshly loaded registry -----
    let removed = Registry::update(&state, |reg| apply(reg, &candidates))?;

    // --- signalling + reporting: OUTSIDE the lock -----------------------------
    // Every signal below is cmdline-identity-gated (no recycled-pid kills).
    let mut bullets = Vec::new();
    for (svc, action) in &removed {
        match action {
            Action::PruneStale => {
                // Best-effort reap of an orphaned cloudflared (a host reboot
                // beats PDEATHSIG), gated on the `cloudflared` cmdline identity.
                if let Some(tpid) = svc.tunnel_pid
                    && proc::pid_matches(tpid, "cloudflared")
                {
                    proc::terminate_orphan(tpid);
                }
                bullets.push((svc.name.clone(), stale_reason(svc)));
            }
            Action::RemoveZombie { reason } => {
                // Foreground zombies were classified SkipForeground above;
                // the assert guards the shell-safety invariant.
                debug_assert!(
                    !svc.foreground,
                    "foreground zombie reached teardown — sanitize must skip it"
                );
                // Signal the group only when a member is confirmed ours —
                // cloudflared lives in the worker's group, so the kill reaches both.
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
            Action::Keep | Action::SkipForeground => {}
        }
    }

    output::print_sanitized(&bullets, &skipped_foreground);
    Ok(())
}

#[cfg(test)]
mod tests {
    //! [`plan`] is a decision table over injected inputs and [`apply`] pure
    //! over a seeded registry — asserted without sockets or signals.
    //! [`worker_alive`] probes real /proc state: the test binary's own pid
    //! is alive but lacks both needles — the recycled-pid scenario.
    //! [`judge`]'s probe overlap is pinned by a real wall-clock bound driven
    //! through the same helper `run` calls (decoy workers; unix only).

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
        // Alive but lacking `--foreground` on the cmdline — the PID-reuse
        // guard reads Some(false), not the Running process_exists would report.
        let mut svc = service(ServiceKind::Static, true);
        svc.worker_pid = std::process::id();
        assert_eq!(worker_alive(&svc), Some(false));
    }

    #[test]
    fn background_self_pid_without_run_worker_reads_dead() {
        // Same guard: the test cmdline lacks the `run-worker` token.
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
        // A live-but-not-ours pid in a foreground slot must classify
        // PruneStale, not SkipForeground (no stranding, no bogus Ctrl-C hint).
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
        // `Some(false)` here comes from the --foreground identity probe, so a
        // recycled pid reads dead; no live signalling is involved.
        let svc = service(ServiceKind::Static, true);
        assert!(matches!(plan(&svc, Some(false), None), Action::PruneStale));
    }

    #[test]
    fn fresh_pid0_reservation_is_kept() {
        // created_at = now keeps the entry inside START_GRACE: reaping now
        // would orphan the just-spawned worker.
        let mut svc = service(ServiceKind::Proxy, false);
        svc.worker_pid = 0;
        svc.public_url = None;
        assert!(matches!(plan(&svc, None, None), Action::Keep));
    }

    #[test]
    fn expired_pid0_reservation_is_pruned() {
        // Past the grace the pid will never land: an abandoned reservation,
        // pruned with nothing to signal (no worker ever landed).
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
        // Shell safety: a foreground zombie is never removed — group-
        // signalling it would kill the operator's shell.
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

    // --- the double-probe (origin_dead_after_double_probe) ---------------------

    /// Bind an ephemeral loopback listener, then drop it: a port that refuses
    /// connections at once (the accepted-risk dead-port pattern).
    fn dead_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn double_probes_overlap_their_reprobe_delay() {
        // Two dead ports judged concurrently must pay ONE 750 ms gap, not two
        // (the serial loop this replaces cost one gap per service), and never
        // LESS than the gap — it is the deliberate mid-restart tolerance.
        // Loopback refuses instantly, so the bounds leave the window pure
        // REPROBE_DELAY plus scheduler noise.
        let port = dead_loopback_port();
        let start = std::time::Instant::now();
        let (first, second) = tokio::join!(
            origin_dead_after_double_probe(port),
            origin_dead_after_double_probe(port)
        );
        let elapsed = start.elapsed();
        assert!(first && second, "a dead port must read dead on both probes");
        assert!(
            elapsed >= REPROBE_DELAY,
            "the reprobe gap is deliberate and must not be shortened: {elapsed:?}"
        );
        assert!(
            elapsed < REPROBE_DELAY * 2,
            "concurrent double-probes must overlap their gaps, took {elapsed:?}"
        );
    }

    // --- the judge loop's concurrency ------------------------------------------

    /// Spawn a decoy live worker: `sh` leading its own process group, argv
    /// carrying the `run-worker` needle `pid_alive` probes for (the trailing
    /// arg is $0, so it stays in argv; the body is a loop — a tail-exec'd
    /// final command would replace argv). The wall-clock harness
    /// (benches/sanitize_median.py) seeds the same shape via a double fork.
    #[cfg(unix)]
    fn spawn_decoy_worker() -> std::process::Child {
        use std::os::unix::process::CommandExt;
        let child = std::process::Command::new("sh")
            .args(["-c", "while :; do sleep 30; done", "run-worker"])
            .process_group(0)
            .spawn()
            .expect("spawn decoy sh");
        // Fork returns before exec completes: spin until the needle is
        // probe-visible, or worker_alive would flake on a blank cmdline.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !proc::pid_alive(child.id()) {
            assert!(
                std::time::Instant::now() < deadline,
                "decoy never became probe-ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        child
    }

    /// Reap the decoy's whole group (the endless loop's current `sleep` is a
    /// grandchild); the negative pid addresses the pgid.
    #[cfg(unix)]
    fn kill_decoy(child: &mut std::process::Child) {
        let pgid = nix::unistd::Pid::from_raw(-(child.id() as i32));
        let _ = nix::sys::signal::kill(pgid, nix::sys::signal::Signal::SIGKILL);
        let _ = child.wait();
    }

    /// THE loop-shape gate: judging FIVE dead-upstream services (the
    /// wall-clock harness's zombie count) through the same [`judge`] `run`
    /// calls must cost ONE 750 ms gap. Five, not two, so that ANY
    /// re-serialization — fully serial, pairwise, or chunked — still runs
    /// >= 2 gaps sequentially and fails the upper bound; a shortened gap
    /// fails the lower. The futures-level test above cannot catch a
    /// re-serialized caller; this one does. Unix-only: the decoy needs `sh`
    /// and a /proc-style cmdline probe.
    #[cfg(unix)]
    #[tokio::test]
    async fn judge_pays_one_reprobe_gap_across_services() {
        let mut decoys = Vec::new();
        let services = (0..5)
            .map(|i| {
                let child = spawn_decoy_worker();
                let mut svc = service(ServiceKind::Proxy, false);
                svc.name = format!("zombie-{i}");
                svc.worker_pid = child.id();
                svc.port = dead_loopback_port();
                decoys.push(child);
                svc
            })
            .collect::<Vec<_>>();

        let start = std::time::Instant::now();
        let (candidates, skipped) = judge(&services).await;
        let elapsed = start.elapsed();

        for child in &mut decoys {
            kill_decoy(child);
        }

        assert!(
            candidates.len() == 5 && skipped.is_empty(),
            "all decoy-backed services must reach RemoveZombie (got {} candidates, \
             skipped {skipped:?})",
            candidates.len()
        );
        assert!(
            elapsed >= REPROBE_DELAY,
            "the gap is the deliberate mid-restart tolerance, never to be shortened: \
             {elapsed:?}"
        );
        assert!(
            elapsed < REPROBE_DELAY * 2,
            "judge must overlap the services' gaps, took {elapsed:?}"
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
        // A concurrent `ft start` re-recorded a different pid: the decision
        // was about the OLD entry — the NEW one must survive.
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
