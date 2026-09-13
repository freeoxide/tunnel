//! The RUN command.
//!
//! `ft run --port <port> -- <command>` spawns the operator's command (a dev
//! server), waits for it to accept connections on the port, then registers the
//! result like any other service: a detached worker owns BOTH the command
//! child and the `cloudflared` Quick Tunnel pointing straight at
//! `http://127.0.0.1:<port>` — identical to PROXY, nothing ft-owned in
//! between. The default background flow mirrors START/PROXY's reserve-entry →
//! spawn-worker → poll-for-URL shape (see `cmd/start.rs`, which is also where
//! the shared foreground machinery lives: `run_foreground_with_command`).
//!
//! The port wait is this command's pre-flight, and it can only run AFTER the
//! child exists (the child IS the server, unlike PROXY's already-running
//! upstream). The reason is the same one that motivates PROXY's pre-flight: a
//! friendly "server never came up" — surfacing the command's captured output —
//! beats a tunnel that comes up happily and then 502s every request. On
//! timeout the worker's process group is torn down (worker + cloudflared +
//! command child together), so a failed run leaves nothing running.
//!
//! Unlike START there is no directory to resolve or confirm — the operator
//! explicitly named the command to publish — so there is no `--yes` flag, and
//! the port must be free (the child has to be able to bind it).

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure};

use crate::cloudflared;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::name;
use crate::output;
use crate::port;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;

/// How long the origin probe waits for the connect to resolve.
///
/// Same value and rationale as `cmd/proxy.rs`'s `PROBE_TIMEOUT` (kept in sync
/// with it): a loopback connect is answered by the local kernel almost
/// instantly (either the accept queue answers or the connection is refused),
/// so this only bounds pathological stacks; it is NOT a request timeout —
/// nothing is ever read from the socket.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Reload cadence while waiting for the worker to publish the public URL.
/// Mirrors START/PROXY's poll loop (whose helpers are private to
/// `cmd/start.rs`).
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Upper bound on how long the parent will wait for BOTH the command's port
/// and the tunnel URL. Dev servers can be slow to boot (bundlers, watchers),
/// so this shares START's 30 s URL budget rather than PROXY's instant
/// pre-flight: the origin here does not exist until the command binds it.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// Most bytes read from a log when surfacing a start-failure reason. Logs can
/// grow large; only the trailing window is examined (the first, partial line
/// after a mid-file seek is skipped).
const LAST_REASON_CAP: u64 = 16 * 1024;

/// Entry point for the RUN command.
pub async fn run(
    port: u16,
    name: Option<String>,
    foreground: bool,
    command: &[OsString],
) -> Result<()> {
    // Refuse before touching any state: an empty `--` tail parses cleanly in
    // clap (a trailing separator with nothing after it), so this is the one
    // check that keeps `ft run --port 3000 --` a usage error rather than a
    // service that would run nothing.
    ensure!(
        !command.is_empty(),
        "no command given after `--` — pass the command to run and tunnel, e.g. \
         `ft run --port 3000 -- npm start`"
    );

    // Unlike PROXY (whose upstream must already exist) the child here has to
    // be able to BIND the port, so an occupied one is a friendly up-front
    // failure instead of a child that dies mid-boot for a non-obvious reason.
    ensure!(
        port::is_port_free(port),
        "port {port} is already in use — the command ft spawns must be able to \
         bind it (is another instance of your server still running?)"
    );

    if foreground {
        // Shared foreground machinery from cmd/start.rs: no static server, ft
        // spawns the command itself and fronts it. The foreground operator is
        // watching the command's output live, so there is deliberately no
        // port-wait here — the "never came up" surface is the command exiting
        // (which tears the tunnel down) rather than a silent timeout.
        crate::cmd::start::run_foreground_with_command(name, Some(port), command).await
    } else {
        run_background(port, name, command).await
    }
}

/// True when something accepts connections on `127.0.0.1:port`.
///
/// Loopback-only by construction (the address is fixed, never
/// caller-supplied). Async with a bounded timeout — this runs inside the poll
/// loop, where a blocking connect would stall the runtime — but never reads
/// from the socket. Duplicated in spirit from `cmd/proxy.rs`'s private
/// `upstream_alive` (the frozen-core split; keep the two in sync): same
/// address discipline, different runtime context.
async fn origin_ready(port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// Display form of the child command for error messages: the full argv,
/// lossily joined (commands are operator-typed and overwhelmingly UTF-8; the
/// message must never fail over a weird byte).
fn command_display(command: &[OsString]) -> String {
    command
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Background flow: reserve the entry, spawn the detached worker (carrying the
/// child command in its argv), then poll for the tunnel URL AND the command's
/// port (failing fast if the worker dies first).
///
/// Mirrors `cmd::start::run_background`/`cmd::proxy::run_background`
/// shape-for-shape, plus the run-specific success condition: cloudflared
/// connects lazily, so a published URL alone proves nothing about the origin —
/// "running" here means the command is actually listening. The poll/fail-fast
/// scaffolding is duplicated rather than shared because the static flow's
/// helpers stay private to `cmd/start.rs` (frozen for this area); keep the
/// three in sync.
async fn run_background(port: u16, name: Option<String>, command: &[OsString]) -> Result<()> {
    let state = StateDir::new()?;

    // --- cloudflared ------------------------------------------------------
    // Looked up BEFORE reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up (same ordering as START/PROXY).
    cloudflared::ensure_installed()?;

    state.ensure()?;

    // --- Reserve name + id + entry atomically -----------------------------
    // Same contract as START/PROXY's reservation, including the M1 protection
    // that comes free: `worker_pid: 0` + a fresh `created_at` puts the entry
    // inside `model::START_GRACE`, so a concurrent `ft kill` / `ft prune`
    // refuses to reap it during the reserve→spawn→record window below (do NOT
    // add any pid-0 staleness handling of our own —
    // `Service::start_in_progress` owns it). Every exit of ours resolves the
    // window quickly: spawn failure, worker death, and the timeout below all
    // remove the entry by id, which bypasses the grace guard (removing our own
    // reservation is always allowed). The command child's pid is NOT known
    // here — the worker spawns it and records `command_pid` itself.
    let (id, name) = Registry::update(&state, |reg| -> Result<(u64, String)> {
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            // Default matches the foreground run flow (`run-{port}` in
            // `cmd::start::run_foreground_inner`) so both modes of `ft run`
            // produce the same name for the same port, mirroring the
            // proxy-{port} convention.
            None => name::unique_name(reg, &format!("run-{port}")),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Run,
            dir: None,
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            command_pid: None,
            static_flags: Default::default(),
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground: false,
        });
        Ok((id, name))
    })??;

    // --- Spawn worker -----------------------------------------------------
    // `dir: None` spawns a directory-less worker; the child command rides in
    // the argv after `--` and only a Run-kind worker ever reads it.
    let worker_pid = match spawn::spawn_worker_with_command(id, &name, None, port, command) {
        Ok(pid) => pid,
        Err(e) => {
            // Release the reserved entry on spawn failure.
            if let Err(cleanup_err) = Registry::update(&state, |reg| {
                reg.remove(id);
            }) {
                tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after spawn failure");
            }
            return Err(e);
        }
    };
    // Record the real worker pid under the lock. Key by the stable numeric id,
    // not the name: the name may be reused for a fresh service after a kill,
    // and an id key is immune to that (and matches how the worker looks itself
    // up), so a concurrent kill cannot make us record the pid against the
    // wrong entry.
    Registry::update(&state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string()) {
            svc.worker_pid = worker_pid;
        }
    })?;

    // --- Poll for the tunnel URL and the command's port -------------------
    // Same mtime-gated loop as START/PROXY (the worker rewrites registry.json
    // only when it discovers the URL or self-removes), with one extra
    // condition: the origin must be answering before we call it a success.
    let registry_path = state.registry_path();
    let mut last_mtime = std::fs::metadata(&registry_path)
        .and_then(|m| m.modified())
        .ok();
    let deadline = Instant::now() + POLL_TIMEOUT;
    let mut origin_up = false;
    loop {
        if Instant::now() >= deadline {
            break;
        }

        // Cheap stat first. Only re-read+parse when the file actually changed.
        let new_mtime = std::fs::metadata(&registry_path)
            .and_then(|m| m.modified())
            .ok();
        // `None` here means "we did NOT re-read this poll" (mtime unchanged);
        // `Some(None)` means we re-read and our entry is gone (vanished).
        let snapshot: Option<Option<Service>> = if new_mtime != last_mtime {
            last_mtime = new_mtime;
            Some(Registry::load(&state)?.find(&id.to_string()).cloned())
        } else {
            // Registry unchanged since last poll: there is no fresh entry to
            // consult, but the worker may still have died silently between
            // rewrites, so probe it directly to preserve fail-fast behaviour.
            // (This uses the pid we already recorded, not the snapshot's.)
            if !proc::pid_alive(worker_pid) {
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                // The URL alone is not success for a run: the origin (the
                // command's port) must answer too. Probe once per poll while
                // waiting; both conditions together are what "started" means.
                origin_up = origin_ready(svc.port).await;
                if origin_up {
                    output::print_started(&svc);
                    return Ok(());
                }
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — reap any survivors, surface
                // the reason inline (the entry is removed below, so we can't
                // send the user to `ft logs` afterwards), then fail fast.
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            Some(None) => {
                // Our entry vanished — a concurrent `ft kill` removed it, or
                // the worker self-removed on its own failure. Tear the worker
                // down and bail now instead of polling the full 30s with a
                // live, orphaned worker that nothing in the registry points
                // at.
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            // Some(Some(svc)) still starting, or None (unchanged registry):
            // poll again.
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out. The worker + cloudflared + command may still be alive and the
    // entry is still active, so tear them all down (the group kill reaches the
    // command child — same group discipline as cloudflared) before bailing.
    // The message depends on WHICH half never arrived: a dead origin gets the
    // command's captured output — a friendly "server never came up" beats a
    // tunnel that would have 502'd every request (same reasoning as PROXY's
    // pre-flight).
    proc::shutdown_process_group(worker_pid).await;
    if let Err(cleanup_err) = Registry::update(&state, |reg| {
        reg.remove(id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after URL timeout");
    }
    let reason = last_reason(&state, &name);
    if origin_up {
        bail!("timed out waiting for the tunnel URL{reason}")
    } else {
        bail!(
            "'{}' never started listening on 127.0.0.1:{port} — the server never \
             came up, so no tunnel was left behind{reason}",
            command_display(command)
        )
    }
}

/// Tear the just-started service down and fail: shared by the poll loop's
/// fail-fast arms (worker death, vanished entry). Shuts the worker's process
/// group down (which reaches cloudflared AND the command child — the group
/// discipline that makes run's teardown orphan-free), removes the registry
/// entry, and surfaces the best log line, which for a run service is usually
/// the command's own captured output.
async fn fail_start(
    state: &StateDir,
    id: &u64,
    name: &str,
    worker_pid: u32,
    command: &[OsString],
    origin_up: bool,
) -> Result<()> {
    proc::shutdown_process_group(worker_pid).await;
    if let Err(cleanup_err) = Registry::update(state, |reg| {
        reg.remove(*id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after worker death");
    }
    let reason = last_reason(state, name);
    if origin_up {
        // The port WAS answering; its death is the command exiting. Same
        // message shape as the never-came-up case, because the operator's
        // next step is the same: read the command's output.
        bail!(
            "'{}' exited before the tunnel came up{reason}",
            command_display(command)
        )
    } else {
        bail!("worker for '{name}' exited before the tunnel came up{reason}")
    }
}

/// Best-effort last non-empty log line to surface in a start-failure message.
///
/// Checks `worker.log` FIRST — unlike START/PROXY, which check `tunnel.log`
/// first — because for a run service the interesting failure is almost always
/// the command's own captured output (its stdout/stderr are teed into
/// worker.log by the worker), not cloudflared's. Returns an empty string if
/// nothing useful is found.
///
/// Duplicated from `cmd/start.rs`/`cmd/proxy.rs` (where it is private) per the
/// frozen-core split of this area; keep the three in sync except for this
/// deliberate ordering flip.
fn last_reason(state: &StateDir, name: &str) -> String {
    let pick = [state.worker_log(name), state.tunnel_log(name)]
        .into_iter()
        .find_map(|p| last_line(&p));
    match pick {
        Some(line) => format!(":\n  {line}"),
        None => String::new(),
    }
}

/// The last non-empty line of `path`, reading at most `LAST_REASON_CAP`
/// trailing bytes so a chatty child cannot make a start-failure message slurp
/// megabytes into memory. Duplicated from `cmd/start.rs`; see [`last_reason`].
fn last_line(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len > LAST_REASON_CAP {
        // Seek into the trailing window; the first "line" then starts mid-file
        // and is likely partial, so drop everything up to the first newline.
        file.seek(SeekFrom::Start(len - LAST_REASON_CAP)).ok()?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let text: &str = if len > LAST_REASON_CAP {
        // Skip the partial first line after a mid-file seek. If the window has
        // no newline at all it is one long line — use it rather than dropping
        // the reason entirely.
        match text.find('\n') {
            Some(i) => &text[i + 1..],
            None => text.as_ref(),
        }
    } else {
        text.as_ref()
    };
    text.lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn origin_ready_accepts_a_live_listener() {
        // Loopback-only sockets: no external network is touched.
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        assert!(
            origin_ready(port).await,
            "a live listener must read as ready"
        );
    }

    #[tokio::test]
    async fn origin_ready_rejects_a_dead_port() {
        // Bind, note the port, then drop the listener: the port is closed
        // again, and nothing else realistically grabs that exact ephemeral
        // port in the microseconds between (same technique as cmd/proxy.rs).
        let port = {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind loopback listener");
            let p = listener.local_addr().expect("local addr").port();
            drop(listener);
            p
        };
        assert!(
            !origin_ready(port).await,
            "a closed port must read as not ready (the never-came-up trigger)"
        );
    }

    #[test]
    fn command_display_joins_the_argv() {
        // Error messages quote the operator's command back to them; the join
        // must keep every argument in order.
        assert_eq!(
            command_display(&["npm".into(), "run".into(), "dev".into()]),
            "npm run dev"
        );
    }
}
