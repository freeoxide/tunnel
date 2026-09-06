//! The `doctor` command: read-only tunnel health diagnostics.
//!
//! The motivating failure mode is a `Proxy` service whose worker and tunnel
//! are happily up while the upstream port it fronts has nothing listening
//! anymore: `cloudflared` answers every request with a 502 and nothing in
//! `ft ls` hints at it — the worker is alive and the URL is published, the
//! tunnel is just fronting a dead origin. `ft doctor` surfaces exactly
//! that, plus the other cheap sanity checks: `cloudflared` discoverable on
//! `PATH`, every registered service's worker still alive, and every
//! service's state directory present on disk.
//!
//! Doctor is strictly diagnostic. It never mutates the registry (it reads
//! through `Registry::load`, the unlocked read-only path — no `ensure`, no
//! `update`, so even a `ft doctor` on a machine with no state at all
//! creates nothing), never signals or kills anything, and never spawns or
//! installs anything: remediation is printed as a `hint:` line naming the
//! command that would fix a finding (`ft kill <name>`, `ft sanitize`, …) and
//! is never executed. Because findings are information rather than command
//! failures, doctor exits 0 whenever it ran at all; only a genuinely broken
//! environment (an unresolvable state dir) exits non-zero through the
//! normal error flow.
//!
//! The origin probe (`origin_alive`) is shared at `pub(crate)` visibility
//! with `cmd/sanitize.rs`, the cleanup counterpart: sanitize removes exactly
//! the services doctor's dead-origin check flags, so the two probe the same
//! port through the same helper rather than keeping a third copy. It still
//! duplicates the tiny `upstream_alive` that stays private to `cmd/proxy.rs`
//! (START's pre-flight) instead of widening that module's API — this repo
//! deliberately duplicates such small helpers (see the "keep the two in
//! sync" notes there). The dead-origin finding's wording mirrors the
//! pre-flight's error message on purpose: both exist to explain that a
//! tunnel fronting a dead port only ever serves 502s.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind, ServiceStatus};
use crate::output;
use crate::state::StateDir;

/// How long the origin probe waits for the connect to resolve.
///
/// Same value and rationale as `cmd/proxy.rs`'s [`PROBE_TIMEOUT`] (kept in
/// sync with it): a loopback connect is answered by the local kernel almost
/// instantly, so this only bounds pathological stacks — nothing is ever read
/// from the socket.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Severity of one check's outcome.
///
/// The summary distinguishes problems (`Warn`/`Fail`) from notes, but the
/// per-line status vocabulary is exactly `ok`/`warn`/`fail`: a note renders
/// as `ok` because it is informational, not a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The check passed, plain and simple.
    Ok,
    /// Informational, not a problem — e.g. a fresh pid-0 reservation inside
    /// the start-grace window. Rendered with the `ok` status word and
    /// counted separately as a note in the summary.
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
    ///
    /// `Note` deliberately renders as `ok`: notes carry no finding, and the
    /// CLI's status vocabulary stays exactly the three words callers can
    /// grep for.
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
    // reports by failing itself (the normal Result → exit-1 flow); every
    // per-check outcome below is informational by contrast.
    let state = StateDir::new()?;

    let mut checks = vec![cloudflared_check()];

    // A missing registry file is the ordinary fresh-install state (load
    // falls back to an empty default → "no services yet", not a finding);
    // an unloadable one IS the finding — corrupt with no usable backup —
    // and per-service checks are skipped because there is nothing to walk.
    match Registry::load(&state) {
        Ok(reg) => {
            for svc in &reg.services {
                let status = svc.status();
                // Probe the origin only when the worker is alive (Running,
                // or Starting with a recorded pid): a dead worker already
                // explains any dead port, and probing a Static service's
                // port whose worker is gone would just duplicate the
                // stale finding.
                let worker_alive = match status {
                    ServiceStatus::Running => true,
                    ServiceStatus::Starting => svc.worker_pid != 0,
                    ServiceStatus::Stale => false,
                };
                let origin = worker_alive.then(|| origin_alive(svc.port));
                checks.extend(service_checks(svc, status, origin));
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

/// The `cloudflared` presence check.
///
/// Uses the raw `which::which` lookup rather than
/// [`crate::cloudflared::ensure_installed`]: that helper bails with the full
/// multi-line install message — right for a start command that cannot
/// proceed, wrong for a single check line — while doctor wants the bare
/// lookup result plus its own one-line hint. A missing `cloudflared` is only
/// a warning (existing tunnels keep running; new starts are what break), and
/// must never fail the command: CI machines without it still get their
/// diagnosis.
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

/// True when something accepts connections on `127.0.0.1:port`.
///
/// `pub(crate)` so `cmd/sanitize.rs` reuses it for its origin double-probe
/// (one shared copy rather than a third). Still duplicated from
/// `cmd/proxy.rs`'s private `upstream_alive` (the pre-flight probe) per this
/// repo's frozen-core split; keep the two in sync. Loopback-only by
/// construction; a blocking `std::net` connect is fine here since doctor (and
/// sanitize, which probes before taking the registry lock) run no other I/O
/// concurrently.
pub(crate) fn origin_alive(port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    std::net::TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).is_ok()
}

/// Build the checks for one service.
///
/// `status` is the service's (already computed) [`Service::status`] — passed
/// in so `run` and the classification below branch on one and the same
/// probe — and `origin` is the origin-probe result, `None` when the probe
/// was skipped because the worker is not alive. With both inputs supplied,
/// this is a pure decision table over `(status, pid, kind, origin,
/// state_dir)`, which is what makes the classification unit-testable
/// without touching the real state dir.
fn service_checks(svc: &Service, status: ServiceStatus, origin: Option<bool>) -> Vec<Check> {
    let mut checks = Vec::new();

    // --- worker liveness --------------------------------------------------
    // `Service::status` already handles every pid subtlety (pid 0 → Starting
    // without probing, foreground vs background probing, PID-reuse safety),
    // so doctor only interprets its verdict — it must not reimplement it.
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
            // A pid-0 reservation: fresh ones are ordinary mid-start state
            // (the parent is inside the reserve→spawn→record window), while
            // one past the grace is an abandoned reservation — the same
            // split `ft prune` makes via `start_in_progress`.
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

    // --- origin probe -----------------------------------------------------
    // Only reached with a live worker (run passes Some only then). This is
    // THE doctor check: a Proxy fronts a port the operator owns, so the
    // port dying underneath a healthy tunnel is invisible to everything
    // else ft prints. For Static the worker itself hosts the server, so a
    // closed port with a live worker contradicts the model — an anomaly,
    // not a certainty.
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
                ServiceKind::Static => checks.push(Check {
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
    //! Unit tests for the probe and the classification table.
    //!
    //! [`service_checks`] is pure given `(status, origin)`, so the whole
    //! matrix (stale / fresh reservation / abandoned reservation / running ×
    //! origin alive-or-dead × kind) is asserted without touching the real
    //! state dir. Liveness inputs reuse the repo's standard tricks: pid 0
    //! needs no probe, 4_000_000 is far outside any real pid namespace, and
    //! the test binary's own pid with `foreground: true` plus a public URL
    //! reads Running through the real `Service::status` (same as model.rs).

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
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
        }
    }

    /// A service whose `status()` reads Running through the real probe: the
    /// test binary's own pid with `foreground: true` (plain existence
    /// probe) and a published public URL.
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
        // Bind, note the port, then drop the listener: the port is closed
        // again, and nothing else realistically grabs that exact ephemeral
        // port in the microseconds between (same pattern as proxy.rs).
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
        // A recorded pid that no longer exists reads Stale through the real
        // status probe: doctor must warn, hint `ft kill`, and NOT emit an
        // origin check (the dead worker already explains any dead port).
        let svc = service(ServiceKind::Proxy);
        let stale = Service {
            worker_pid: 4_000_000,
            ..svc
        };
        let checks = service_checks(&stale, stale.status(), None);
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
        // created_at = now puts the pid-0 reservation inside START_GRACE:
        // the parent may be mid reserve→spawn→record, so this is a note
        // (status word ok), not a finding.
        let svc = service(ServiceKind::Proxy);
        let checks = service_checks(&svc, svc.status(), None);
        let worker = find(&checks, "worker alpha");
        assert_eq!(worker.status, CheckStatus::Note);
        assert_eq!(worker.status.as_str(), "ok");
        assert!(worker.hint.is_none(), "a note carries no remediation");
    }

    #[test]
    fn expired_pid0_reservation_warns_with_sanitize_hint() {
        // Past the grace the pid will never land (the parent died
        // mid-start): an abandoned reservation, removable — the same split
        // `ft prune` makes, and sanitize is the cleanup command doctor now
        // points at.
        let mut svc = service(ServiceKind::Proxy);
        svc.created_at = crate::model::now_utc()
            - (TimeDelta::from_std(crate::model::START_GRACE).expect("grace fits")
                + TimeDelta::seconds(1));
        let checks = service_checks(&svc, svc.status(), None);
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
        // THE motivating case: worker Running, upstream port dead. The
        // finding must say the tunnel will 502 every request and hint at
        // starting the upstream or `ft kill`.
        let svc = running_service(ServiceKind::Proxy);
        let checks = service_checks(&svc, svc.status(), Some(false));
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
        // The worker itself is healthy — only the origin check fails.
        assert_eq!(find(&checks, "worker alpha").status, CheckStatus::Ok);
    }

    #[test]
    fn live_static_with_dead_origin_is_an_anomaly_warn() {
        // A Static worker hosts its own server, so a live worker with a
        // closed port contradicts the model: report the anomaly (warn, not
        // the proxy's fail — the tunnel is not fronting an operator-owned
        // port here) and point at the logs.
        let svc = running_service(ServiceKind::Static);
        let checks = service_checks(&svc, svc.status(), Some(false));
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
        // The healthy service: worker Running, origin answering, state dir
        // present (a real tempdir, since the existence check hits the fs).
        // Every check is ok and none carries a hint.
        let mut svc = running_service(ServiceKind::Proxy);
        let dir = tempfile::tempdir().expect("create temp state dir");
        svc.state_dir = dir.path().to_path_buf();
        let checks = service_checks(&svc, svc.status(), Some(true));
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
        // A path inside our own private tempdir that nothing ever creates:
        // guaranteed-absent, unlike a hard-coded /tmp path a shared machine
        // might happen to have.
        let dir = tempfile::tempdir().expect("create temp state dir");
        let mut svc = running_service(ServiceKind::Proxy);
        svc.state_dir = dir.path().join("never-created");
        let checks = service_checks(&svc, svc.status(), Some(true));
        let state_dir = find(&checks, "state-dir alpha");
        assert_eq!(state_dir.status, CheckStatus::Warn);
        assert!(
            state_dir.detail.contains("missing"),
            "got: {}",
            state_dir.detail
        );
    }
}
