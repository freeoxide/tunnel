//! The detached worker process.
//!
//! Invoked as `ft run-worker --id --name --dir --port`, this binds the static
//! server on `127.0.0.1` (fail-fast if the port cannot be bound), spawns the
//! `cloudflared` Quick Tunnel child, discovers the tunnel URL from cloudflared's
//! output, records it on the registry entry, and stays alive until cloudflared
//! exits, the server task ends, or a terminating signal arrives.
//!
//! All registry writes go through [`Registry::update`] (an exclusive flock), so
//! the parent's writes and ours never clobber each other.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use crate::cloudflared;
use crate::error::Result;
use crate::model::Registry;
use crate::state::StateDir;
use crate::static_server;

/// How long to keep retrying the registry load looking for our entry.
const REGISTRY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const REGISTRY_LOOKUP_INTERVAL: Duration = Duration::from_millis(100);
/// Grace window after SIGTERM before SIGKILL'ing cloudflared.
const CLOUDFLARED_GRACE: Duration = Duration::from_secs(2);
/// Upper bound on how long we wait for in-flight requests to drain after
/// signalling graceful shutdown. If a request is stuck, we abort the server
/// task as a fallback so it can't hang the worker indefinitely.
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Run the worker to completion.
pub async fn run(id: u64, name: String, dir: PathBuf, port: u16) -> Result<()> {
    let state = StateDir::new()?;
    let worker_log = state.worker_log(&name);
    let server_log = state.server_log(&name);
    let tunnel_log = state.tunnel_log(&name);

    init_tracing(&worker_log, &server_log);

    tracing::info!(
        "worker starting: id={id} name={name:?} dir={} port={port}",
        dir.display()
    );

    // Recover our registry entry (parent race). The parent reserves the entry
    // before spawning us, but there is a window before the atomic save lands.
    // Look up by id, not name: if a stale worker is still draining while the
    // parent reuses this name for a new service, a name lookup would bind us to
    // the wrong entry. The id is unique and stable.
    let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_TIMEOUT;
    let mut found_entry = false;
    while std::time::Instant::now() < deadline {
        let located = Registry::update(&state, |reg| {
            if let Some(svc) = reg.find_mut(&id.to_string()) {
                // Self-register our pid if the parent never recorded it (e.g. it
                // died between spawn and recording), so `ft kill` can still
                // reach us.
                if svc.worker_pid == 0 {
                    svc.worker_pid = std::process::id();
                }
                true
            } else {
                false
            }
        })?;
        if located {
            found_entry = true;
            break;
        }
        tokio::time::sleep(REGISTRY_LOOKUP_INTERVAL).await;
    }
    if !found_entry {
        // Dying worker mustn't leave a permanent stale entry; clear ours by id.
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("registry entry for service id={id} never appeared");
    }

    // Bind the listener now (fail-fast): if the port is taken, the worker exits
    // immediately and the parent's poll detects the dead worker instead of
    // waiting out the full timeout with a dead tunnel returning 502s.
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            // Dying worker mustn't leave a permanent stale entry.
            let _ = Registry::update(&state, |reg| {
                reg.remove(id);
            });
            return Err(e).with_context(|| format!("failed to bind 127.0.0.1:{port}"));
        }
    };
    tracing::info!("static server bound on 127.0.0.1:{port}");

    let router = static_server::router(dir.clone());

    // Graceful shutdown channel: on the teardown path we fire `shutdown_tx`,
    // which lets axum stop accepting and drain in-flight requests instead of
    // aborting the server task (and dropping the requests) mid-flight.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut server_handle = tokio::spawn(async move {
        static_server::serve_on(router, listener, async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // cloudflared
    if let Err(e) = cloudflared::ensure_installed() {
        tracing::error!(%e, "cloudflared unavailable");
        // Nothing is serving the tunnel yet; tear the static server down
        // gracefully (it may already have accepted connections).
        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut server_handle).await;
        // Dying worker mustn't leave a permanent stale entry.
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        return Err(e);
    }
    let mut child = match cloudflared::spawn(port, tunnel_log.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%e, "failed to spawn cloudflared");
            let _ = shutdown_tx.send(());
            let _ = tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut server_handle).await;
            // Dying worker mustn't leave a permanent stale entry.
            let _ = Registry::update(&state, |reg| {
                reg.remove(id);
            });
            return Err(e);
        }
    };
    let tunnel_pid = child.id();
    tracing::info!(?tunnel_pid, "cloudflared tunnel spawned");

    // Tee cloudflared output to tunnel.log and scan for the URL (first wins).
    let url_found = Arc::new(AtomicBool::new(false));
    let log_writer = Arc::new(Mutex::new(
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&tunnel_log)
            .await
            .with_context(|| format!("opening tunnel log {}", tunnel_log.display()))?,
    ));

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let ctx = ReaderCtx {
        id,
        name: name.clone(),
        state: state.clone(),
        tunnel_pid,
        url_found: url_found.clone(),
        log_writer: log_writer.clone(),
    };

    let mut reader_tasks = Vec::new();
    if let Some(out) = stdout {
        reader_tasks.push(tokio::spawn(pipe_stream(BufReader::new(out), ctx.clone())));
    }
    if let Some(err) = stderr {
        reader_tasks.push(tokio::spawn(pipe_stream(BufReader::new(err), ctx.clone())));
    }

    // Keep alive until cloudflared exits, the server task ends, or we're
    // signalled. Polling server_handle ensures a serve failure (post-bind) is
    // observed rather than silently lost.
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    let mut sig_int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("installing SIGINT handler")?;

    let exit_reason = tokio::select! {
        status = child.wait() => {
            match status {
                Ok(s) => tracing::info!(?s, "cloudflared exited"),
                Err(e) => tracing::error!(%e, "waiting on cloudflared failed"),
            }
            ReaderExit::ChildExited
        }
        res = &mut server_handle => {
            match res {
                Ok(Ok(())) => tracing::info!("static server task ended"),
                Ok(Err(e)) => tracing::error!(%e, "static server task failed"),
                Err(e) => tracing::error!(%e, "static server task panicked"),
            }
            ReaderExit::ServerEnded
        }
        _ = sig_term.recv() => {
            tracing::info!("received SIGTERM, shutting down");
            ReaderExit::Signal
        }
        _ = sig_int.recv() => {
            tracing::info!("received SIGINT, shutting down");
            ReaderExit::Signal
        }
    };

    // If cloudflared may still be alive, shut it down and reap it to avoid a
    // transient zombie. On ChildExited the select's wait() already reaped it.
    if matches!(exit_reason, ReaderExit::Signal | ReaderExit::ServerEnded) {
        if let Some(pid) = tunnel_pid {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        if tokio::time::timeout(CLOUDFLARED_GRACE, child.wait())
            .await
            .is_err()
            && let Some(pid) = tunnel_pid
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = child.wait().await; // ensure reaped
    }

    for task in reader_tasks {
        task.abort();
    }

    // Drain in-flight requests: fire the shutdown signal and let axum finish
    // what it's serving, with a bounded timeout so a stuck request can't hang
    // the worker. If the drain doesn't complete in time, abort as a fallback.
    let _ = shutdown_tx.send(());
    match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut server_handle).await {
        Ok(Ok(Ok(()))) => tracing::info!("static server drained and exited"),
        Ok(Ok(Err(e))) => tracing::error!(%e, "static server task failed during shutdown"),
        Ok(Err(e)) => tracing::error!(%e, "static server task panicked during shutdown"),
        Err(_) => {
            tracing::warn!(
                "static server did not drain within {:?}, aborting",
                SERVER_SHUTDOWN_TIMEOUT
            );
            server_handle.abort();
        }
    }

    tracing::info!("worker exiting");
    Ok(())
}

/// Why the keep-alive loop ended — drives cloudflared teardown.
enum ReaderExit {
    ChildExited,
    ServerEnded,
    Signal,
}

/// Shared context handed to each output-reader task.
#[derive(Clone)]
struct ReaderCtx {
    /// Numeric id — the lookup key for registry writes (unique & stable, unlike
    /// `name`, which the parent may reuse for a fresh service after a kill).
    id: u64,
    /// Display only — used in log messages, never as a registry key.
    name: String,
    state: StateDir,
    tunnel_pid: Option<u32>,
    url_found: Arc<AtomicBool>,
    log_writer: Arc<Mutex<tokio::fs::File>>,
}

/// Read a cloudflared output stream line by line, tee each line to tunnel.log,
/// and publish the first discovered Quick Tunnel URL onto the registry entry.
async fn pipe_stream<R>(reader: BufReader<R>, ctx: ReaderCtx)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = reader.lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                {
                    let mut f = ctx.log_writer.lock().await;
                    let _ = f.write_all(line.as_bytes()).await;
                    let _ = f.write_all(b"\n").await;
                    let _ = f.flush().await;
                }

                if !ctx.url_found.load(Ordering::Acquire)
                    && let Some(url) = cloudflared::extract_url(&line)
                    && !ctx.url_found.swap(true, Ordering::AcqRel)
                {
                    tracing::info!(%url, "discovered tunnel URL");
                    if let Err(e) = publish_url(&ctx, url) {
                        tracing::error!(%e, "failed to record tunnel URL");
                    }
                }
            }
            Ok(None) => break, // EOF
            Err(e) => {
                tracing::warn!(%e, "error reading cloudflared output stream");
                break;
            }
        }
    }
}

/// Record the discovered `url` (and the tunnel pid, if known) on the registry
/// entry for `ctx.id` under an exclusive lock. Looks up by id so a stale worker
/// draining alongside a name-reuse can't clobber the freshly-reused name's entry.
fn publish_url(ctx: &ReaderCtx, url: String) -> Result<()> {
    let id = ctx.id;
    let name = &ctx.name;
    let tunnel_pid = ctx.tunnel_pid;
    Registry::update(&ctx.state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string()) {
            svc.public_url = Some(url.clone());
            if svc.tunnel_pid.is_none() {
                svc.tunnel_pid = tunnel_pid;
            }
        } else {
            tracing::warn!("service id={id} ({name}) vanished before URL could be recorded");
        }
    })
}

/// Initialise `tracing`: tower_http request traces go to `server.log`, while
/// worker/ft traces go to `worker.log`. Fire-once; a no-op if a subscriber is
/// already installed.
fn init_tracing(worker_log: &Path, server_log: &Path) {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::Mutex;
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    // tower_http request traces -> server.log; everything else -> worker.log.
    // Each layer is Option-wrapped so a failure to open one log file just drops
    // that sink rather than aborting tracing setup. Mode 0600: server.log can
    // carry request URIs.
    let server_layer = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(server_log)
        .ok()
        .map(|f| {
            fmt::layer()
                .with_writer(Mutex::new(f))
                .with_ansi(false)
                .with_filter(EnvFilter::new("tower_http=trace"))
        });

    let worker_layer = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(worker_log)
        .ok()
        .map(|f| {
            fmt::layer()
                .with_writer(Mutex::new(f))
                .with_ansi(false)
                .with_filter(EnvFilter::new("info,tower_http=off"))
        });

    let _ = tracing_subscriber::registry()
        .with(server_layer)
        .with(worker_layer)
        .try_init();
}
