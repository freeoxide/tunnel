//! The HOOK command.
//!
//! `ft hook` runs an ft-owned webhook receiver/inspector origin (see
//! `hook_server`) behind a cloudflared Quick Tunnel and registers the result
//! like any other service. The background flow shares START/PROXY's
//! reserve-entry → spawn-worker → poll-for-URL scaffolding (see
//! `cmd/start.rs`); the worker binds the origin itself on `127.0.0.1:<port>`
//! (fail-fast on a bind error), so success is "URL published" — no separate
//! origin probe.
//!
//! Unlike RUN there is no child command, and unlike PROXY the port is ft's
//! own (it must be FREE, not already listening), exactly like the static
//! server. The foreground flow keeps its own body (the origin is the hook
//! server, not a static dir or a command child) but shares the reservation,
//! guard, and announce helpers from `cmd/start.rs`; keep its teardown order in
//! sync with `run_foreground_inner` there.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

use super::start;
use crate::cloudflared;
use crate::error::Result;
use crate::model::ServiceKind;
use crate::port;
use crate::server::hook_server::{self, HookLog};
use crate::spawn;
use crate::state::StateDir;

/// Entry point for the HOOK command.
pub async fn run(
    port: Option<u16>,
    name: Option<String>,
    foreground: bool,
    keep: Option<u16>,
) -> Result<()> {
    // The hook origin is ft's own server, so the port must be FREE — the
    // inverse of PROXY's pre-flight, same reasoning: a friendly up-front
    // failure beats a tunnel fronting nothing (or a worker that dies on its
    // bind check seconds later). Resolved BEFORE any state is touched so a
    // rejection leaves zero state.
    let port = match port {
        Some(p) => {
            ensure!(
                port::is_port_free(p),
                "port {p} is already in use — ft's hook origin needs to bind it \
                 (is another instance still running?)"
            );
            p
        }
        None => port::allocate_free_port()?,
    };
    // Retention is bounded to 1..=1000 by clap's value parser, so it always
    // fits the u16 the worker argv carries.
    let keep = keep.unwrap_or(hook_server::DEFAULT_KEEP);

    if foreground {
        run_foreground(port, name, keep).await
    } else {
        run_background(port, name, keep).await
    }
}

/// Open (and create the parent dir for) a hook service's request store.
fn open_hook_log(
    state: &StateDir,
    name: &str,
    keep: u16,
) -> Result<Arc<std::sync::Mutex<HookLog>>> {
    state.ensure_service_dir(name)?;
    let path = state.service_dir(name).join(hook_server::REQUESTS_FILENAME);
    // load fails fast on a non-NotFound read error (the store may be intact
    // behind it) — surface the disk problem at startup, never rename over it.
    let log = HookLog::load(path.clone(), usize::from(keep))
        .with_context(|| format!("opening hook request store {}", path.display()))?;
    Ok(Arc::new(std::sync::Mutex::new(log)))
}

/// Background flow: reserve the entry, spawn the detached HOOK worker (which
/// binds the origin itself), then poll for the tunnel URL (failing fast if
/// the worker dies first) — the shared START/PROXY scaffolding.
async fn run_background(port: u16, name: Option<String>, keep: u16) -> Result<()> {
    let state = StateDir::new()?;

    // Looked up before reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up.
    cloudflared::ensure_installed()?;

    state.ensure()?;

    let (id, name) = start::reserve_entry(
        &state,
        ServiceKind::Hook,
        None, // a hook serves no directory; its records live in requests.json
        format!("hook-{port}"),
        port,
        name,
        0,
        false,
        Default::default(),
    )?;

    // `dir: None` + `--keep` spawns a directory-less HOOK worker; its arm
    // binds the origin and opens the request store.
    let worker_pid = match spawn::spawn_hook_worker(id, &name, port, keep) {
        Ok(pid) => pid,
        Err(e) => {
            start::remove_reservation(&state, id);
            return Err(e);
        }
    };
    start::record_worker_pid(&state, id, worker_pid)?;

    start::poll_for_url(&state, id, &name, worker_pid).await
}

/// Why the foreground keep-alive loop ended. A hook foreground has no command
/// child, so unlike `cmd/start.rs`'s enum there is no `CommandExited` arm.
enum ReaderExit {
    ChildExited,
    Signal,
}

/// Foreground flow: run the hook origin and tunnel in this process and block
/// until cloudflared exits, Ctrl-C is received, or (Unix) SIGTERM arrives.
/// Mirrors `cmd/start.rs::run_foreground_inner`'s teardown order; hook
/// differences: the kind is always Hook, the origin is the hook server, and
/// there is no command child.
async fn run_foreground(port: u16, name: Option<String>, keep: u16) -> Result<()> {
    use crate::server::static_server;

    let state = StateDir::new()?;
    state.ensure()?;

    cloudflared::ensure_installed()?;

    let (id, name) = start::reserve_entry(
        &state,
        ServiceKind::Hook,
        None,
        format!("hook-{port}"),
        port,
        name,
        std::process::id(),
        true,
        Default::default(),
    )?;

    // From here, every exit path must release the reserved entry.
    let _entry = start::EntryGuard::new(state.clone(), id);

    // Tee cloudflared output to tunnel.log so `ft logs <name>` works for
    // foreground tunnels (which otherwise only print to the terminal).
    let tunnel_log = state.tunnel_log(&name);
    let log_writer = Arc::new(Mutex::new(
        crate::fsutil::open_private_append_async(&tunnel_log)
            .await
            .with_context(|| format!("opening tunnel log {}", tunnel_log.display()))?,
    ));

    // Install the SIGTERM handler (Unix) BEFORE spawning the server +
    // cloudflared: if it fails, the `?` returns with only the
    // (guard-protected) entry to clean up — no orphaned server task or
    // cloudflared child is left behind.
    #[cfg(unix)]
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    // The origin: ft's own hook server in THIS process. `serve` binds
    // 127.0.0.1:<port> (pre-flighted for freeness above) and installs its own
    // Ctrl-C drain; the JoinHandle is kept so the drain can be bounded below.
    let hook_log = open_hook_log(&state, &name, keep)?;
    let router = hook_server::router(hook_log);
    let mut server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "hook server exited with error");
        }
    });

    let mut child = match cloudflared::spawn(port) {
        Ok(c) => c,
        Err(e) => {
            // Abort the just-spawned server task; the entry is released by
            // the guard on return.
            server_handle.abort();
            return Err(e);
        }
    };
    let tunnel_pid = child.id();

    // Mirror cloudflared's combined output to stdout AND tunnel.log, and
    // publish the public URL on first discovery.
    let found = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    if let Some(out) = child.stdout.take() {
        tasks.push(tokio::spawn(start::drain_and_announce(
            BufReader::new(out).lines(),
            found.clone(),
            name.clone(),
            port,
            state.clone(),
            id,
            tunnel_pid,
            log_writer.clone(),
        )));
    }
    if let Some(err) = child.stderr.take() {
        tasks.push(tokio::spawn(start::drain_and_announce(
            BufReader::new(err).lines(),
            found.clone(),
            name.clone(),
            port,
            state.clone(),
            id,
            tunnel_pid,
            log_writer.clone(),
        )));
    }

    // Keep the foreground alive until cloudflared exits, Ctrl-C is received,
    // or (Unix) SIGTERM arrives. Racing child.wait() ensures that if
    // cloudflared dies before the URL is found (or any time later) we tear
    // down instead of hanging forever.
    #[cfg(unix)]
    let exit_reason = tokio::select! {
        status = child.wait() => {
            match status {
                Ok(s) => tracing::info!(?s, "cloudflared exited"),
                Err(e) => tracing::error!(%e, "waiting on cloudflared failed"),
            }
            ReaderExit::ChildExited
        }
        _ = sig_term.recv() => {
            tracing::info!("received SIGTERM, shutting down foreground hook");
            ReaderExit::Signal
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl-C, shutting down foreground hook");
            ReaderExit::Signal
        }
    };
    #[cfg(not(unix))]
    let exit_reason = tokio::select! {
        status = child.wait() => {
            match status {
                Ok(s) => tracing::info!(?s, "cloudflared exited"),
                Err(e) => tracing::error!(%e, "waiting on cloudflared failed"),
            }
            ReaderExit::ChildExited
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl-C, shutting down foreground hook");
            ReaderExit::Signal
        }
    };

    // If cloudflared may still be alive, shut it down and reap it (on
    // ChildExited the select's wait() already reaped it).
    if matches!(exit_reason, ReaderExit::Signal) {
        cloudflared::shutdown(tunnel_pid, &mut child).await;
    }

    for task in tasks {
        task.abort();
    }

    // `serve`'s own Ctrl-C handler has already begun draining on Ctrl-C;
    // bound it so a stuck request can't hang the command, falling back to
    // abort.
    match tokio::time::timeout(start::SERVER_SHUTDOWN_TIMEOUT, &mut server_handle).await {
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(
                "hook server did not drain within {:?}, aborting",
                start::SERVER_SHUTDOWN_TIMEOUT
            );
            server_handle.abort();
        }
    }

    // The `_entry` guard removes our registry entry on return (every exit
    // path).
    Ok(())
}
