//! The `doctor` command: read-only tunnel health diagnostics.
//!
//! Headline: a live tunnel whose origin port has nothing listening — a Proxy
//! fronting a dead upstream 502s every request, invisible to `ft ls`. Plus
//! `cloudflared` on PATH, worker liveness, state dir presence, and for `Run`
//! services the orphan case: worker dead while the recorded command lives
//! (no cmdline needle exists for an operator command — identity is
//! best-effort, so the wording never attributes the pid or port outright).
//! Strictly diagnostic: `Registry::load` only (creates nothing), no signals,
//! no spawns; remediation is a printed `hint:`, never executed; exits 0
//! unless the state dir is unresolvable. [`origin_alive`] is shared with
//! `cmd/sanitize.rs` and `cmd/proxy.rs`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::PROBE_TIMEOUT;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind, ServiceStatus};
use crate::output;
use crate::proc;
use crate::state::StateDir;

/// Severity of one check's outcome; the per-line vocabulary is exactly
/// `ok`/`warn`/`fail` — a `Note` renders as `ok` (informational, no finding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    /// Informational, not a problem — e.g. a fresh pid-0 reservation inside
    /// the start-grace window; renders as `ok`, counted separately.
    Note,
    /// A problem that does not break serving right now (a stale entry, a
    /// missing state dir, an absent `cloudflared`).
    Warn,
    /// A problem that breaks the tunnel right now (a live proxy whose
    /// upstream port has nothing listening — every request 502s).
    Fail,
}

impl CheckStatus {
    /// The leading status word of a check line.
    pub fn as_str(self) -> &'static str {
        match self {
            CheckStatus::Ok | CheckStatus::Note => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }

    /// True for the two severities that count towards the summary's problem
    /// tally.
    pub fn is_problem(self) -> bool {
        matches!(self, CheckStatus::Warn | CheckStatus::Fail)
    }
}

/// The result of one diagnostic check, rendered as a single line by
/// [`output::print_doctor`].
#[derive(Debug)]
pub struct Check {
    /// What was checked (`cloudflared`, `registry`, `worker <name>`, …).
    pub name: String,
    /// Outcome severity.
    pub status: CheckStatus,
    /// Human-readable one-line result (the line's payload after the colon).
    pub detail: String,
    /// Remediation printed on an indented `hint:` line after a problem.
    /// Only ever set on problem severities; `None` means "nothing to do".
    pub hint: Option<String>,
}

/// Entry point for the DOCTOR command.
pub async fn run() -> Result<()> {
    // A broken state-dir resolution is the one environment failure doctor
    // reports by failing itself; every per-check outcome is informational.
    let state = StateDir::new()?;

    let mut checks = vec![cloudflared_check()];

    // A missing registry file is the ordinary fresh-install state (load
    // falls back to empty); an unloadable one IS the finding.
    match Registry::load(&state) {
        Ok(reg) => {
            for svc in &reg.services {
                let status = svc.status();
                // Probe the origin only when the worker is alive: a dead
                // worker already explains any dead port.
                let worker_alive = match status {
                    ServiceStatus::Running => true,
                    ServiceStatus::Starting => svc.worker_pid != 0,
                    ServiceStatus::Stale => false,
                };
                let origin = worker_alive.then(|| origin_alive(svc.port));
                let command = command_probe(svc);
                checks.extend(service_checks(svc, status, origin, command));
            }
        }
        Err(e) => checks.push(Check {
            name: "registry".to_string(),
            status: CheckStatus::Fail,
            detail: format!("cannot be loaded ({e})"),
            hint: Some(format!(
                "repair or remove {} — with it unreadable, every registry-backed \
                 command is blocked",
                state.registry_path().display()
            )),
        }),
    }

    output::print_doctor(&checks);
    Ok(())
}

/// `cloudflared` presence. Raw `which::which` — `ensure_installed` bails
/// with the full install message; a miss is a warn, never a failure.
fn cloudflared_check() -> Check {
    match which::which("cloudflared") {
        Ok(path) => Check {
            name: "cloudflared".to_string(),
            status: CheckStatus::Ok,
            detail: format!("found at {}", path.display()),
            hint: None,
        },
        Err(_) => Check {
            name: "cloudflared".to_string(),
            status: CheckStatus::Warn,
            detail: "not found on PATH".to_string(),
            hint: Some(
                "install it from https://developers.cloudflare.com/cloudflare-one/\
                 connections/connect-networks/downloads/ (macOS: brew install \
                 cloudflared, Windows: winget install Cloudflare.cloudflared)"
                    .to_string(),
            ),
        },
    }
}

/// True when something accepts connections on `127.0.0.1:port` — shared
/// `pub(crate)` so one probe copy exists; blocking connect is fine here.
pub(crate) fn origin_alive(port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    std::net::TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).is_ok()
}

/// Liveness probes for a `Run` service's recorded command child, fed into
/// [`service_checks`] so the orphan decision stays a pure table.
#[derive(Debug, Clone, Copy)]
struct CommandProbe {
    /// The recorded pid, echoed back for the finding wording.
    pid: u32,
    /// Plain existence probe — deliberately NOT identity: no cmdline needle
    /// exists for an operator command, so a recycled pid reads alive.
    alive: bool,
    /// Whether the run's own port answers — evidence, never identity proof;
    /// probed unconditionally so its meaning never depends on `alive`.
    port_alive: bool,
}

/// Probe a `Run` service's recorded command child, if any. Pid 0 is refused
/// like unrecorded: probing it reads the CALLER's own group as "alive".
fn command_probe(svc: &Service) -> Option<CommandProbe> {
    if svc.kind != ServiceKind::Run {
        return None;
    }
    let pid = svc.command_pid.filter(|p| *p != 0)?;
    Some(CommandProbe {
        pid,
        alive: proc::process_exists(pid),
        port_alive: origin_alive(svc.port),
    })
}

/// Build the checks for one service — a pure decision table over `(status,
/// pid, kind, origin, command, state_dir)`, unit-testable without the real
/// state dir. `origin` is the probe result, `None` when skipped because the
/// worker is not alive; `command` is the Run-only child probe.
fn service_checks(
    svc: &Service,
    status: ServiceStatus,
    origin: Option<bool>,
    command: Option<CommandProbe>,
) -> Vec<Check> {
    let mut checks = Vec::new();

    // --- worker liveness --------------------------------------------------
    // `Service::status` handles every pid subtlety (pid 0, foreground vs
    // background, PID-reuse safety); doctor only interprets its verdict.
    match (status, svc.worker_pid) {
        (ServiceStatus::Stale, _) => checks.push(Check {
            name: format!("worker {}", svc.name),
            status: CheckStatus::Warn,
            detail: format!("worker process (pid {}) is not running", svc.worker_pid),
            hint: Some(format!(
                "run `ft kill {}` to remove the entry (or `ft sanitize` to clean up \
                 everything dangling)",
                svc.name
            )),
        }),
        (ServiceStatus::Starting, 0) => {
            // A pid-0 reservation: fresh ones are ordinary mid-start state;
            // one past the grace is abandoned (`ft prune` splits the same way).
            if svc.start_in_progress() {
                checks.push(Check {
                    name: format!("worker {}", svc.name),
                    status: CheckStatus::Note,
                    detail: "fresh reservation inside the start-grace window — the \
                             worker pid lands momentarily; not an error"
                        .to_string(),
                    hint: None,
                });
            } else {
                checks.push(Check {
                    name: format!("worker {}", svc.name),
                    status: CheckStatus::Warn,
                    detail: "worker pid was never recorded and the start grace has \
                             expired — the reservation was abandoned mid-start"
                        .to_string(),
                    hint: Some("run `ft sanitize` to remove the abandoned reservation".to_string()),
                });
            }
        }
        (ServiceStatus::Starting, _) => checks.push(Check {
            name: format!("worker {}", svc.name),
            status: CheckStatus::Ok,
            detail: format!(
                "worker pid {} is alive; public URL not discovered yet",
                svc.worker_pid
            ),
            hint: None,
        }),
        (ServiceStatus::Running, _) => checks.push(Check {
            name: format!("worker {}", svc.name),
            status: CheckStatus::Ok,
            detail: format!("worker pid {} is running", svc.worker_pid),
            hint: None,
        }),
    }

    // --- run command child: orphan detection ---------------------------------
    // Only a Stale worker can orphan anything — a live worker owns its child.
    // The pid is existence-probed only (no needle exists), so neither branch
    // may attribute the live pid or the port outright — a recycled pid plus
    // an unrelated squatter must not become a false orphan claim; one shared
    // verify-first hint serves both branches.
    if status == ServiceStatus::Stale
        && let Some(probe) = command
        && probe.alive
    {
        let detail = if probe.port_alive {
            format!(
                "tunnel dead, command still running: pid {} is alive and \
                 127.0.0.1:{} still answers — most likely the command \
                 outliving its worker, though the unverified pid could also \
                 be a recycled one",
                probe.pid, svc.port
            )
        } else {
            format!(
                "tunnel dead, command still running: a process exists at \
                 the recorded pid {}, but nothing listens on 127.0.0.1:{} \
                 — either the command survived without serving, or the pid \
                 was recycled by an unrelated process",
                probe.pid, svc.port
            )
        };
        checks.push(Check {
            name: format!("command {}", svc.name),
            status: CheckStatus::Warn,
            detail,
            hint: Some(format!(
                "check what pid {} is and stop it if it is the command; \
                 `ft kill {}` removes the stale entry (the kill cannot \
                 signal the command: the worker that owned the group is gone)",
                probe.pid, svc.name
            )),
        });
    }

    // --- origin probe -----------------------------------------------------
    // THE doctor check: a Proxy fronts an operator-owned port whose death is
    // invisible to everything else ft prints; ft-hosted kinds: anomaly only.
    if let Some(alive) = origin {
        if alive {
            checks.push(Check {
                name: format!("origin {}", svc.name),
                status: CheckStatus::Ok,
                detail: format!("127.0.0.1:{} is answering", svc.port),
                hint: None,
            });
        } else {
            match svc.kind {
                ServiceKind::Proxy => checks.push(Check {
                    name: format!("origin {}", svc.name),
                    status: CheckStatus::Fail,
                    detail: format!(
                        "proxying {} but nothing is listening — the tunnel will 502 \
                         every request",
                        svc.port
                    ),
                    hint: Some(format!(
                        "start the upstream server, or stop the service (`ft kill {}` — `ft \
                         sanitize` cleans background dead-upstream tunnels; stop a \
                         foreground one with Ctrl-C in its terminal)",
                        svc.name
                    )),
                }),
                // A run service 502s exactly like a proxy; the recorded
                // command pid tells WHICH story (never bound / exited / etc).
                ServiceKind::Run => {
                    let (state, hint) = match command {
                        Some(p) if p.alive => (
                            format!("the command (pid {}) is running but not listening", p.pid),
                            format!(
                                "check the command's output (`ft logs {}`); stop the \
                                 service with `ft kill {}` if it is wedged",
                                svc.name, svc.name
                            ),
                        ),
                        Some(p) => (
                            format!("the command (recorded pid {}) has exited", p.pid),
                            format!(
                                "the worker's monitor should tear the service down \
                                 momentarily; `ft kill {}` removes it if it lingers",
                                svc.name
                            ),
                        ),
                        None => (
                            "no command pid is recorded yet".to_string(),
                            format!("check the command's output (`ft logs {}`)", svc.name),
                        ),
                    };
                    checks.push(Check {
                        name: format!("origin {}", svc.name),
                        status: CheckStatus::Fail,
                        detail: format!(
                            "run: nothing is listening on 127.0.0.1:{} — {}, so \
                             the tunnel will 502 every request",
                            svc.port, state
                        ),
                        hint: Some(hint),
                    });
                }
                // Hook/Drop host in-process like Static — anomaly, not
                // certainty; command_probe is Run-gated (these are probe-free).
                ServiceKind::Static | ServiceKind::Hook | ServiceKind::Drop => checks.push(Check {
                    name: format!("origin {}", svc.name),
                    status: CheckStatus::Warn,
                    detail: format!(
                        "worker pid {} is alive but nothing is listening on \
                         127.0.0.1:{} — the built-in server should be; this is an \
                         anomaly",
                        svc.worker_pid, svc.port
                    ),
                    hint: Some(format!(
                        "inspect its logs (`ft logs {}`) or restart it (`ft kill {}`, \
                         then start it again)",
                        svc.name, svc.name
                    )),
                }),
            }
        }
    }

    // --- state dir --------------------------------------------------------
    let state_ok = svc.state_dir.exists();
    checks.push(Check {
        name: format!("state-dir {}", svc.name),
        status: if state_ok {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        detail: if state_ok {
            format!("present at {}", svc.state_dir.display())
        } else {
            format!(
                "missing ({}) — this service's logs cannot be read",
                svc.state_dir.display()
            )
        },
        hint: (!state_ok).then(|| {
            format!(
                "run `ft kill {}` and start the service again to recreate it",
                svc.name
            )
        }),
    });

    checks
}

#[cfg(test)]
mod tests {
    //! [`service_checks`] is pure given `(status, origin, command)`, so the
    //! whole matrix is asserted without the real state dir. Fixtures: pid 0
    //! needs no probe, 4_000_000 is outside any real pid namespace, and the
    //! test binary's own pid + `foreground: true` + a public URL reads Running.

    use super::*;
    use chrono::TimeDelta;
    use std::path::PathBuf;

    fn service(kind: ServiceKind) -> Service {
        Service {
            id: 1,
            name: "alpha".to_string(),
            kind,
            dir: (kind == ServiceKind::Static).then(|| PathBuf::from("/tmp/dir")),
            port: 3000,
            local_url: "http://127.0.0.1:3000".to_string(),
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

    /// Reads Running through the real probe: the test binary's own pid with
    /// `foreground: true` and a published public URL.
    fn running_service(kind: ServiceKind) -> Service {
        let mut s = service(kind);
        s.foreground = true;
        s.worker_pid = std::process::id();
        s.public_url = Some("https://x.trycloudflare.com".to_string());
        s
    }

    /// The check whose name starts with `prefix` (e.g. "worker alpha").
    fn find<'a>(checks: &'a [Check], prefix: &str) -> &'a Check {
        checks
            .iter()
            .find(|c| c.name == prefix)
            .unwrap_or_else(|| panic!("no check named {prefix:?} in {checks:?}"))
    }

    #[test]
    fn origin_alive_accepts_a_live_listener() {
        // Loopback-only sockets: no external network is touched.
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        assert!(origin_alive(port), "a live listener must read as alive");
    }

    #[test]
    fn origin_alive_rejects_a_dead_port() {
        // Bind then drop the listener: nothing else grabs that exact
        // ephemeral port in between.
        let port = {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind loopback listener");
            let p = listener.local_addr().expect("local addr").port();
            drop(listener);
            p
        };
        assert!(
            !origin_alive(port),
            "a closed port must read as dead (the 502 finding's trigger)"
        );
    }

    #[test]
    fn stale_worker_warns_with_kill_hint_and_skips_the_probe() {
        // 4_000_000 reads Stale through the real status probe.
        let svc = service(ServiceKind::Proxy);
        let stale = Service {
            worker_pid: 4_000_000,
            ..svc
        };
        let checks = service_checks(&stale, stale.status(), None, None);
        let worker = find(&checks, "worker alpha");
        assert_eq!(worker.status, CheckStatus::Warn);
        assert!(worker.detail.contains("not running"));
        assert!(
            worker
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("ft kill alpha"),
            "the hint must name `ft kill alpha`, got: {:?}",
            worker.hint
        );
        assert!(
            worker
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("ft sanitize"),
            "the general-cleanup hint must name `ft sanitize`, got: {:?}",
            worker.hint
        );
        assert!(
            checks.iter().all(|c| c.name != "origin alpha"),
            "no origin check may accompany a dead worker: {checks:?}"
        );
    }

    #[test]
    fn fresh_pid0_reservation_is_a_note_not_an_error() {
        // created_at = now puts the reservation inside START_GRACE: mid-start
        // is a note, not a finding.
        let svc = service(ServiceKind::Proxy);
        let checks = service_checks(&svc, svc.status(), None, None);
        let worker = find(&checks, "worker alpha");
        assert_eq!(worker.status, CheckStatus::Note);
        assert_eq!(worker.status.as_str(), "ok");
        assert!(worker.hint.is_none(), "a note carries no remediation");
    }

    #[test]
    fn expired_pid0_reservation_warns_with_sanitize_hint() {
        // Past the grace the pid will never land: an abandoned reservation,
        // same split `ft prune` makes; sanitize is the cleanup command.
        let mut svc = service(ServiceKind::Proxy);
        svc.created_at = crate::model::now_utc()
            - (TimeDelta::from_std(crate::model::START_GRACE).expect("grace fits")
                + TimeDelta::seconds(1));
        let checks = service_checks(&svc, svc.status(), None, None);
        let worker = find(&checks, "worker alpha");
        assert_eq!(worker.status, CheckStatus::Warn);
        assert!(
            worker
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("ft sanitize"),
            "the hint must name `ft sanitize`, got: {:?}",
            worker.hint
        );
    }

    #[test]
    fn live_proxy_with_dead_origin_fails_with_the_502_wording() {
        // The motivating case for the whole command.
        let svc = running_service(ServiceKind::Proxy);
        let checks = service_checks(&svc, svc.status(), Some(false), None);
        let origin = find(&checks, "origin alpha");
        assert_eq!(origin.status, CheckStatus::Fail);
        assert!(
            origin
                .detail
                .contains("proxying 3000 but nothing is listening"),
            "expected the fixed dead-upstream wording, got: {}",
            origin.detail
        );
        assert!(origin.detail.contains("502"), "got: {}", origin.detail);
        let hint = origin.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("start the upstream server") && hint.contains("ft kill alpha"),
            "unexpected hint: {hint}"
        );
        assert!(
            hint.contains("ft sanitize"),
            "the hint must also name the bulk cleanup, got: {hint}"
        );
        assert_eq!(find(&checks, "worker alpha").status, CheckStatus::Ok);
    }

    #[test]
    fn live_static_with_dead_origin_is_an_anomaly_warn() {
        // Static hosts its own server, so a live worker with a closed port is
        // an anomaly warn, not the proxy's fail.
        let svc = running_service(ServiceKind::Static);
        let checks = service_checks(&svc, svc.status(), Some(false), None);
        let origin = find(&checks, "origin alpha");
        assert_eq!(origin.status, CheckStatus::Warn);
        assert!(origin.detail.contains("anomaly"), "got: {}", origin.detail);
        assert!(
            origin
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("ft logs alpha"),
            "unexpected hint: {:?}",
            origin.hint
        );
    }

    #[test]
    fn live_worker_with_answering_origin_and_state_dir_is_all_ok() {
        // A real tempdir, since the existence check hits the fs.
        let mut svc = running_service(ServiceKind::Proxy);
        let dir = tempfile::tempdir().expect("create temp state dir");
        svc.state_dir = dir.path().to_path_buf();
        let checks = service_checks(&svc, svc.status(), Some(true), None);
        assert!(
            checks
                .iter()
                .all(|c| c.status == CheckStatus::Ok && c.hint.is_none()),
            "a healthy service must be all-ok with no hints: {checks:?}"
        );
        assert!(
            find(&checks, "origin alpha")
                .detail
                .contains("is answering")
        );
    }

    #[test]
    fn missing_state_dir_is_a_minor_warn() {
        // A never-created path inside our own tempdir: guaranteed-absent,
        // unlike a hard-coded /tmp path a shared machine might have.
        let dir = tempfile::tempdir().expect("create temp state dir");
        let mut svc = running_service(ServiceKind::Proxy);
        svc.state_dir = dir.path().join("never-created");
        let checks = service_checks(&svc, svc.status(), Some(true), None);
        let state_dir = find(&checks, "state-dir alpha");
        assert_eq!(state_dir.status, CheckStatus::Warn);
        assert!(
            state_dir.detail.contains("missing"),
            "got: {}",
            state_dir.detail
        );
    }

    // --- run command child: orphan detection ---------------------------------

    /// Reads Stale through the real probe (pid far outside any namespace)
    /// with an optional recorded command pid.
    fn stale_run(command_pid: Option<u32>) -> Service {
        Service {
            worker_pid: 4_000_000,
            command_pid,
            ..service(ServiceKind::Run)
        }
    }

    #[test]
    fn stale_run_with_a_live_listening_command_flags_the_orphan() {
        // A recycled pid almost never listens on the run's port — the
        // likelier-orphan reading; ft kill cannot reach it, stop by hand.
        let svc = stale_run(Some(4242));
        let checks = service_checks(
            &svc,
            svc.status(),
            None,
            Some(CommandProbe {
                pid: 4242,
                alive: true,
                port_alive: true,
            }),
        );
        let command = find(&checks, "command alpha");
        assert_eq!(command.status, CheckStatus::Warn);
        assert!(
            command
                .detail
                .contains("tunnel dead, command still running"),
            "expected the orphan wording, got: {}",
            command.detail
        );
        assert!(
            command.detail.contains("4242") && command.detail.contains("127.0.0.1:3000"),
            "the finding must name the pid and the port, got: {}",
            command.detail
        );
        // The port answer is evidence, not proof — the wording must not
        // claim orphanhood outright nor drop the recycled reading.
        assert!(
            !command.detail.contains("an orphaned process"),
            "the detail must not claim orphanhood outright: {}",
            command.detail
        );
        assert!(
            command.detail.contains("recycled"),
            "the detail must keep the recycled-pid reading open, got: {}",
            command.detail
        );
        let hint = command.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("4242") && hint.contains("ft kill alpha"),
            "the hint must say how to stop the orphan and clean the entry, got: {hint}"
        );
        assert!(
            hint.contains("if it is the command"),
            "the hint must say to verify the pid first, got: {hint}"
        );
        assert_eq!(find(&checks, "worker alpha").status, CheckStatus::Warn);
        assert!(
            checks.iter().all(|c| c.name != "origin alpha"),
            "no origin check may accompany a dead worker: {checks:?}"
        );
    }

    #[test]
    fn stale_run_with_a_live_but_silent_command_hedges_the_finding() {
        // pid alive, port dead: either a survivor that stopped serving or a
        // recycled pid — reported, but hedged.
        let svc = stale_run(Some(4242));
        let checks = service_checks(
            &svc,
            svc.status(),
            None,
            Some(CommandProbe {
                pid: 4242,
                alive: true,
                port_alive: false,
            }),
        );
        let command = find(&checks, "command alpha");
        assert_eq!(command.status, CheckStatus::Warn);
        assert!(
            command
                .detail
                .contains("tunnel dead, command still running")
                && command.detail.contains("recycled"),
            "expected the hedged orphan wording, got: {}",
            command.detail
        );
        assert!(
            command
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("ft kill alpha")
                && command
                    .hint
                    .as_deref()
                    .unwrap_or_default()
                    .contains("if it is the command"),
            "the hint must be the shared verify-first cleanup hint, got: {:?}",
            command.hint
        );
    }

    #[test]
    fn stale_run_with_a_dead_command_pid_adds_no_command_finding() {
        // The ordinary post-mortem: worker and command both gone.
        let svc = stale_run(Some(4242));
        let checks = service_checks(
            &svc,
            svc.status(),
            None,
            Some(CommandProbe {
                pid: 4242,
                alive: false,
                port_alive: true,
            }),
        );
        assert!(
            checks.iter().all(|c| c.name != "command alpha"),
            "a dead command is not a finding: {checks:?}"
        );
        assert_eq!(find(&checks, "worker alpha").status, CheckStatus::Warn);
    }

    #[test]
    fn stale_run_without_a_recorded_command_pid_has_nothing_to_flag() {
        // No recorded pid: no command child is knowable.
        let svc = stale_run(None);
        let checks = service_checks(&svc, svc.status(), None, None);
        assert!(
            checks.iter().all(|c| c.name != "command alpha"),
            "no command check without a recorded pid: {checks:?}"
        );
    }

    #[test]
    fn live_run_with_dead_origin_and_live_command_names_the_running_pid() {
        // The command has not bound the port — a 502-ing tunnel, with the
        // running pid named so the operator looks at the right process.
        let svc = running_service(ServiceKind::Run);
        let checks = service_checks(
            &svc,
            svc.status(),
            Some(false),
            Some(CommandProbe {
                pid: 4242,
                alive: true,
                port_alive: false,
            }),
        );
        let origin = find(&checks, "origin alpha");
        assert_eq!(origin.status, CheckStatus::Fail);
        assert!(
            origin
                .detail
                .contains("the command (pid 4242) is running but not listening")
                && origin.detail.contains("502"),
            "got: {}",
            origin.detail
        );
        assert!(
            origin
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("ft logs alpha"),
            "unexpected hint: {:?}",
            origin.hint
        );
        assert!(
            checks.iter().all(|c| c.name != "command alpha"),
            "a live worker owns its command — no separate command check: {checks:?}"
        );
    }

    #[test]
    fn live_run_with_dead_origin_and_exited_command_says_so() {
        // The command exited; the worker's monitor should end the service
        // within moments.
        let svc = running_service(ServiceKind::Run);
        let checks = service_checks(
            &svc,
            svc.status(),
            Some(false),
            Some(CommandProbe {
                pid: 4242,
                alive: false,
                port_alive: false,
            }),
        );
        let origin = find(&checks, "origin alpha");
        assert_eq!(origin.status, CheckStatus::Fail);
        assert!(
            origin
                .detail
                .contains("the command (recorded pid 4242) has exited"),
            "got: {}",
            origin.detail
        );
    }

    #[test]
    fn live_run_with_dead_origin_and_no_recorded_pid_says_the_spawn_has_not_landed() {
        // Mid-spawn or recording failed — the finding must not invent a pid.
        let svc = running_service(ServiceKind::Run);
        let checks = service_checks(&svc, svc.status(), Some(false), None);
        let origin = find(&checks, "origin alpha");
        assert_eq!(origin.status, CheckStatus::Fail);
        assert!(
            origin.detail.contains("no command pid is recorded yet"),
            "got: {}",
            origin.detail
        );
    }

    #[test]
    fn healthy_run_service_is_all_ok_and_names_no_command() {
        // No "command" line on a healthy service — it only carries findings.
        let mut svc = running_service(ServiceKind::Run);
        let dir = tempfile::tempdir().expect("create temp state dir");
        svc.state_dir = dir.path().to_path_buf();
        let checks = service_checks(
            &svc,
            svc.status(),
            Some(true),
            Some(CommandProbe {
                pid: 4242,
                alive: true,
                port_alive: true,
            }),
        );
        assert!(
            checks
                .iter()
                .all(|c| c.status == CheckStatus::Ok && c.hint.is_none()),
            "a healthy run service must be all-ok with no hints: {checks:?}"
        );
        assert!(
            checks.iter().all(|c| c.name != "command alpha"),
            "no command check on a healthy service: {checks:?}"
        );
    }

    #[test]
    fn hand_edited_run_entry_with_a_dir_is_classified_unchanged() {
        // Registry::validate tolerates a hand-edited Run entry with a `dir`
        // (unlike proxy-with-dir): doctor classifies it identically.
        let mut svc = stale_run(Some(4242));
        svc.dir = Some(PathBuf::from("/tmp/hand-edited"));
        let checks = service_checks(
            &svc,
            svc.status(),
            None,
            Some(CommandProbe {
                pid: 4242,
                alive: true,
                port_alive: true,
            }),
        );
        let command = find(&checks, "command alpha");
        assert_eq!(command.status, CheckStatus::Warn);
        assert!(
            command
                .detail
                .contains("tunnel dead, command still running"),
            "got: {}",
            command.detail
        );
    }

    // --- command_probe: the Run-only probe policy -----------------------------

    #[test]
    fn command_probe_skips_non_run_kinds_unrecorded_and_zero_pids() {
        // A command_pid on a Proxy is hand-edited nonsense; pid 0 would probe
        // the CALLER's own group. All arms return before any syscall.
        let mut proxy = service(ServiceKind::Proxy);
        proxy.command_pid = Some(4242);
        assert!(
            command_probe(&proxy).is_none(),
            "a proxy has no command child to probe"
        );
        let mut unrecorded = service(ServiceKind::Run);
        unrecorded.command_pid = None;
        assert!(
            command_probe(&unrecorded).is_none(),
            "no recorded pid, nothing to probe"
        );
        let mut zero = service(ServiceKind::Run);
        zero.command_pid = Some(0);
        assert!(
            command_probe(&zero).is_none(),
            "pid 0 must be refused, not probed against the caller's group"
        );
    }

    #[test]
    fn command_probe_reads_real_liveness_and_port_state() {
        // Real probes with controlled answers: the test's own pid + a bound
        // listener; port_alive is probed even for a dead pid.
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        let mut svc = service(ServiceKind::Run);
        svc.port = port;
        svc.local_url = format!("http://127.0.0.1:{port}");
        svc.command_pid = Some(std::process::id());
        let probe = command_probe(&svc).expect("a recorded run pid must probe");
        assert!(probe.alive, "the test's own pid must read alive");
        assert!(
            probe.port_alive,
            "the freshly bound listener must read as answering"
        );
        assert_eq!(probe.pid, std::process::id());

        svc.command_pid = Some(4_000_000);
        let probe = command_probe(&svc).expect("a recorded run pid must probe");
        assert!(!probe.alive, "4_000_000 is outside any real pid namespace");
        assert!(
            probe.port_alive,
            "the port is probed unconditionally, not only for a live pid"
        );
    }
}
