//! The RUN command.
//!
//! `ft run --port <port> -- <command>` spawns the operator's command (a dev
//! server), waits for it to accept connections on the port, then registers the
//! result like any other service: a detached worker owns BOTH the command
//! child and the `cloudflared` Quick Tunnel pointing straight at
//! `http://127.0.0.1:<port>` — identical to PROXY. The default background flow
//! uses the shared reserve-entry → spawn-worker → poll-for-URL scaffolding
//! (see `cmd/start.rs`, which also hosts the shared foreground machinery
//! `run_foreground_with_command`).
//!
//! The port wait is this command's pre-flight and can only run AFTER the child
//! exists (the child IS the server, unlike PROXY's already-running upstream):
//! a friendly "server never came up" — surfacing the command's captured output
//! — beats a tunnel that comes up happily and then 502s every request. On
//! timeout the worker's process group is torn down (worker + cloudflared; the
//! worker's teardown relays to the command's group, which the child leads), so
//! a failed run leaves nothing running.
//!
//! Unlike START there is no directory to resolve or confirm, so there is no
//! `--yes` flag, and the port must be free (the child has to bind it).

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use anyhow::{bail, ensure};

use super::{POLL_INTERVAL, POLL_TIMEOUT, start};
use crate::cloudflared;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::output;
use crate::port;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;

/// How long the origin probe waits for the connect to resolve. A loopback
/// connect is answered by the local kernel almost instantly, so this only
/// bounds pathological stacks; nothing is ever read from the socket.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

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

/// True when something accepts connections on `127.0.0.1:port` — the async
/// twin of `doctor::origin_alive` (this runs inside the poll loop, where a
/// blocking connect would stall the runtime). Loopback-only by construction;
/// nothing is ever read from the socket.
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

/// Background flow: reserve the entry, spawn the detached worker (carrying
/// the child command in its argv), then poll for the tunnel URL AND the
/// command's port (failing fast if the worker dies first). Unlike the shared
/// poll loop, a published URL alone is not success: cloudflared connects
/// lazily, so "running" means the command is actually listening.
async fn run_background(port: u16, name: Option<String>, command: &[OsString]) -> Result<()> {
    let state = StateDir::new()?;

    // --- cloudflared ------------------------------------------------------
    // Looked up BEFORE reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up (same ordering as START/PROXY).
    cloudflared::ensure_installed()?;

    state.ensure()?;

    // --- Reserve name + id + entry atomically -----------------------------
    // The shared reservation (see `cmd/start.rs::reserve_entry`), including
    // the START_GRACE protection during the reserve→spawn→record window. The
    // command child's pid is NOT known here — the worker spawns it and
    // records `command_pid` itself.
    let (id, name) = start::reserve_entry(
        &state,
        ServiceKind::Run,
        None,
        format!("run-{port}"),
        port,
        name,
        0,
        false,
        Default::default(),
    )?;

    // --- Spawn worker -----------------------------------------------------
    // `dir: None` spawns a directory-less worker; the child command rides in
    // the argv after `--` and only a Run-kind worker ever reads it.
    let worker_pid = match spawn::spawn_worker_with_command(id, &name, None, port, command) {
        Ok(pid) => pid,
        Err(e) => {
            start::remove_reservation(&state, id);
            return Err(e);
        }
    };
    start::record_worker_pid(&state, id, worker_pid)?;

    // --- Poll for the tunnel URL and the command's port -------------------
    // Same mtime-gated loop as the shared poll (the worker rewrites
    // registry.json only when it discovers the URL or self-removes), with one
    // extra condition: cloudflared connects lazily, so a published URL alone
    // proves nothing about the origin — "running" means the command is
    // actually listening too.
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

        // Cheap stat first; re-read+parse only when the file changed.
        let new_mtime = std::fs::metadata(&registry_path)
            .and_then(|m| m.modified())
            .ok();
        // `None` = did NOT re-read this poll (mtime unchanged); `Some(None)`
        // = re-read and our entry is gone (vanished).
        let snapshot: Option<Option<Service>> = if new_mtime != last_mtime {
            last_mtime = new_mtime;
            Some(Registry::load(&state)?.find(&id.to_string()).cloned())
        } else {
            // Registry unchanged: probe the recorded pid directly to keep the
            // fail-fast behaviour (the worker may have died silently between
            // rewrites).
            if !proc::pid_alive(worker_pid) {
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                // The URL alone is not success for a run: the origin (the
                // command's port) must answer too.
                origin_up = origin_ready(svc.port).await;
                if origin_up {
                    output::print_started(&svc);
                    return Ok(());
                }
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — surface the reason inline
                // (the entry is removed, so the user cannot go to `ft logs`
                // afterwards).
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            Some(None) => {
                // Our entry vanished — a concurrent `ft kill`, or the worker
                // self-removed on its own failure. Tear the worker down now
                // instead of polling the full 30 s with a live orphan.
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            // Still starting, or unchanged registry: poll again.
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out: the worker + cloudflared + command may still be alive, so
    // tear them all down (the group kill takes the worker and cloudflared
    // down directly; the worker's teardown relays to the command child's
    // group). The message depends on WHICH half never arrived: a dead origin
    // gets the command's captured output — same reasoning as PROXY's
    // pre-flight.
    start::teardown(&state, id, worker_pid, "URL timeout").await;
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

/// Tear the just-started service down and fail: the poll loop's fail-fast
/// arms (worker death, vanished entry). The group kill reaches cloudflared
/// directly while the worker's own teardown relays to the command child's
/// group; the surfaced reason for a run is usually the command's own output.
async fn fail_start(
    state: &StateDir,
    id: &u64,
    name: &str,
    worker_pid: u32,
    command: &[OsString],
    origin_up: bool,
) -> Result<()> {
    start::teardown(state, *id, worker_pid, "worker death").await;
    let reason = last_reason(state, name);
    if origin_up {
        // The port WAS answering; its death is the command exiting. Same
        // message shape as the never-came-up case: the operator's next step
        // is the same — read the command's output.
        bail!(
            "'{}' exited before the tunnel came up{reason}",
            command_display(command)
        )
    } else {
        bail!("worker for '{name}' exited before the tunnel came up{reason}")
    }
}

/// Best-effort last non-empty log line for a start-failure message. Unlike
/// the shared `start::last_reason` (tunnel.log first), a run checks
/// `worker.log` first: the interesting failure is almost always the command's
/// own captured output, teed into worker.log by the worker.
fn last_reason(state: &StateDir, name: &str) -> String {
    let pick = [state.worker_log(name), state.tunnel_log(name)]
        .into_iter()
        .find_map(|p| start::last_line(&p));
    match pick {
        Some(line) => format!(":\n  {line}"),
        None => String::new(),
    }
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
        // port in the microseconds between (same technique as cmd/doctor.rs).
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
