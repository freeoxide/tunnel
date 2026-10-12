//! The `sanitize` command: remove every dangling service (stale entries,
//! zombie upstreams). Probes run before the registry lock; hits re-verified
//! under it (id AND worker_pid); signals sent outside it. Foreground never killed.

use std::time::Duration;

use crate::cmd::doctor::origin_alive_async;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::output;
use crate::proc;
use crate::state::StateDir;

const REPROBE_DELAY: Duration = Duration::from_millis(750);

enum ZombieReason {
    UpstreamDead,
    InProcessServerDead,
}

impl ZombieReason {
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

enum Action {
    Keep,
    PruneStale,
    RemoveZombie { reason: ZombieReason },
    SkipForeground,
}

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

fn plan(svc: &Service, worker_alive: Option<bool>, port_dead: Option<bool>) -> Action {
    match worker_alive {
        Some(false) => return Action::PruneStale,
        None => {
            return if svc.start_in_progress() {
                Action::Keep
            } else {
                Action::PruneStale
            };
        }
        Some(true) => {}
    }

    if svc.public_url.is_none() {
        return Action::Keep;
    }

    match port_dead {
        Some(true) if svc.foreground => Action::SkipForeground,
        Some(true) => Action::RemoveZombie {
            reason: match svc.kind {
                ServiceKind::Proxy | ServiceKind::Run => ZombieReason::UpstreamDead,
                ServiceKind::Static | ServiceKind::Hook | ServiceKind::Drop => {
                    ZombieReason::InProcessServerDead
                }
            },
        },
        _ => Action::Keep,
    }
}

struct Judgment {
    svc: Service,
    action: Action,
}

fn stale_reason(svc: &Service) -> String {
    if svc.worker_pid == 0 {
        "worker pid was never recorded — the start reservation was abandoned".to_string()
    } else {
        "worker no longer running".to_string()
    }
}

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

async fn origin_dead_after_double_probe(port: u16) -> bool {
    if origin_alive_async(port).await {
        return false;
    }
    tokio::time::sleep(REPROBE_DELAY).await;
    !origin_alive_async(port).await
}

async fn judge(services: &[Service]) -> (Vec<Judgment>, Vec<String>) {
    let mut liveness = Vec::with_capacity(services.len());
    let mut probes = Vec::with_capacity(services.len());
    for svc in services {
        let alive = worker_alive(svc);
        let probe = (alive == Some(true) && svc.public_url.is_some())
            .then(|| tokio::spawn(origin_dead_after_double_probe(svc.port)));
        liveness.push(alive);
        probes.push(probe);
    }

    let mut candidates = Vec::new();
    let mut skipped_foreground = Vec::new();
    for ((svc, alive), probe) in services.iter().zip(liveness).zip(probes) {
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

    let snapshot = Registry::load(&state)?;

    if snapshot.services.is_empty() {
        output::print_sanitized(&[], &[]);
        return Ok(());
    }

    let (candidates, skipped_foreground) = judge(&snapshot.services).await;

    let removed = Registry::update(&state, |reg| apply(reg, &candidates))?;

    let mut bullets = Vec::new();
    for (svc, action) in &removed {
        match action {
            Action::PruneStale => {
                if let Some(tpid) = svc.tunnel_pid
                    && proc::pid_matches(tpid, "cloudflared")
                {
                    proc::terminate_orphan(tpid);
                }
                bullets.push((svc.name.clone(), stale_reason(svc)));
            }
            Action::RemoveZombie { reason } => {
                debug_assert!(
                    !svc.foreground,
                    "foreground zombie reached teardown — sanitize must skip it"
                );
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

    #[test]
    fn foreground_self_pid_without_the_flag_reads_dead() {
        let mut svc = service(ServiceKind::Static, true);
        svc.worker_pid = std::process::id();
        assert_eq!(worker_alive(&svc), Some(false));
    }

    #[test]
    fn background_self_pid_without_run_worker_reads_dead() {
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
        let mut svc = service(ServiceKind::Static, true);
        svc.worker_pid = std::process::id();
        let alive = worker_alive(&svc);
        assert!(matches!(plan(&svc, alive, Some(true)), Action::PruneStale));
    }

    #[test]
    fn dead_background_worker_is_pruned() {
        let svc = service(ServiceKind::Static, false);
        assert!(matches!(plan(&svc, Some(false), None), Action::PruneStale));
    }

    #[test]
    fn dead_foreground_worker_is_pruned() {
        let svc = service(ServiceKind::Static, true);
        assert!(matches!(plan(&svc, Some(false), None), Action::PruneStale));
    }

    #[test]
    fn fresh_pid0_reservation_is_kept() {
        let mut svc = service(ServiceKind::Proxy, false);
        svc.worker_pid = 0;
        svc.public_url = None;
        assert!(matches!(plan(&svc, None, None), Action::Keep));
    }

    #[test]
    fn expired_pid0_reservation_is_pruned() {
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
        let mut svc = service(ServiceKind::Proxy, false);
        svc.public_url = None;
        assert!(matches!(plan(&svc, Some(true), None), Action::Keep));
    }

    #[test]
    fn running_service_with_answering_port_is_kept() {
        let svc = service(ServiceKind::Proxy, false);
        assert!(matches!(plan(&svc, Some(true), Some(false)), Action::Keep));
    }

    #[test]
    fn running_service_without_a_probe_is_kept() {
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

    fn dead_loopback_port() -> u16 {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn double_probes_overlap_their_reprobe_delay() {
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

    #[cfg(unix)]
    fn spawn_decoy_worker() -> std::process::Child {
        use std::os::unix::process::CommandExt;
        let child = std::process::Command::new("sh")
            .args(["-c", "while :; do sleep 30; done", "run-worker"])
            .process_group(0)
            .spawn()
            .expect("spawn decoy sh");
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

    #[cfg(unix)]
    fn kill_decoy(child: &mut std::process::Child) {
        let pgid = nix::unistd::Pid::from_raw(-(child.id() as i32));
        let _ = nix::sys::signal::kill(pgid, nix::sys::signal::Signal::SIGKILL);
        let _ = child.wait();
    }

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
        let judged = service(ServiceKind::Static, false);
        let mut reg = Registry::default();
        let candidates = [Judgment {
            svc: judged,
            action: Action::PruneStale,
        }];
        let removed = apply(&mut reg, &candidates);
        assert!(removed.is_empty());
    }
}
