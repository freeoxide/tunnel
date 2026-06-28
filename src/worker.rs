//! The detached worker process.
//!
//! Invoked as `ft run-worker --id --name --dir --port`, this runs the static
//! server in-process (bound to `127.0.0.1` only) and owns the `cloudflared`
//! Quick Tunnel child. It discovers the tunnel URL from cloudflared's output,
//! records it (plus the tunnel pid) on the registry entry, and then stays
//! alive until cloudflared exits or a terminating signal arrives.
//!
//! The parent START command only reads the registry: it does not wait on this
//! process. We therefore poll the registry to recover the entry the parent
//! wrote (which can land a moment after we are spawned), and we update that
//! same entry in place when the URL becomes known.

use std::path::PathBuf;
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

/// How long to keep retrying the registry load looking for our entry, before
/// giving up. The parent writes the entry immediately after spawning us, but
/// there is an inherent race between `spawn()` returning and the atomic
/// `registry.save()` completing.
const REGISTRY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
/// Interval between registry reload attempts while waiting for our entry.
const REGISTRY_LOOKUP_INTERVAL: Duration = Duration::from_millis(100);

/// Run the worker to completion.
///
/// Returns `Ok(())` on a clean shutdown (signal received or cloudflared
/// exited) and `Err` if the static server fails to start or cloudflared cannot
/// be launched. Errors are logged via `tracing` before propagating so the
/// user sees a reason in `worker.log`.
pub async fn run(id: u64, name: String, dir: PathBuf, port: u16) -> Result<()> {
    // Resolve our state directory and per-service log paths up front; tracing
    // needs worker.log before anything else.
    let state = StateDir::new()?;
    let worker_log = state.worker_log(&name);
    let tunnel_log = state.tunnel_log(&name);

    init_tracing(&worker_log);

    tracing::info!(
        "worker starting: id={id} name={name:?} dir={} port={port}",
        dir.display()
    );

    // --- Recover our registry entry (parent race) -------------------------
    // The parent allocates the id and writes the entry right after spawning
    // us, but there is a window where the entry is not yet on disk. Retry
    // briefly rather than failing immediately.
    let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_TIMEOUT;
    let mut found_entry = false;
    while std::time::Instant::now() < deadline {
        let registry = Registry::load(&state)?;
        if registry.find(&name).is_some() {
            found_entry = true;
            break;
        }
        tokio::time::sleep(REGISTRY_LOOKUP_INTERVAL).await;
    }
    if !found_entry {
        tracing::error!(
            "registry entry for {name:?} not found after waiting; parent may have aborted"
        );
        anyhow::bail!("registry entry for service {name:?} never appeared");
    }

    // --- Static server ----------------------------------------------------
    let router = static_server::router(dir.clone());
    let server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "static server exited with error");
            return Err(e);
        }
        Ok(())
    });
    tracing::info!("static server task spawned on 127.0.0.1:{port}");

    // --- cloudflared ------------------------------------------------------
    if let Err(e) = cloudflared::ensure_installed() {
        tracing::error!(%e, "cloudflared unavailable");
        server_handle.abort();
        return Err(e);
    }

    let mut child = match cloudflared::spawn(port, tunnel_log.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%e, "failed to spawn cloudflared");
            server_handle.abort();
            return Err(e);
        }
    };
    let tunnel_pid = child.id();
    tracing::info!(?tunnel_pid, "cloudflared tunnel spawned");

    // Tee cloudflared's combined output to tunnel.log and scan for the URL.
    // Only the first discovery wins; later matches are ignored.
    let url_found = Arc::new(AtomicBool::new(false));
    let log_writer = Arc::new(Mutex::new(
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&tunnel_log)
            .await
            .with_context(|| format!("opening tunnel log {}", tunnel_log.display()))?,
    ));

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let ctx = ReaderCtx {
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

    // --- Keep alive until cloudflared exits or we are signaled ------------
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    let mut sig_int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("installing SIGINT handler")?;

    let exit_reason = tokio::select! {
        status = child.wait() => {
            match status {
                Ok(s) => {
                    tracing::info!(?s, "cloudflared exited");
                    ReaderExit::ChildExited
                }
                Err(e) => {
                    tracing::error!(%e, "waiting on cloudflared failed");
                    ReaderExit::ChildExited
                }
            }
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

    // On a signal, terminate cloudflared ourselves; on child exit there is
    // nothing more to signal. Best-effort: ignore "no such process".
    if matches!(exit_reason, ReaderExit::Signal) {
        if let Some(pid) = tunnel_pid {
            tracing::debug!(pid, "sending SIGTERM to cloudflared");
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }

    // Stop reading cloudflared output and tear down the server.
    for task in reader_tasks {
        task.abort();
    }
    server_handle.abort();

    // The registry entry is intentionally left in place: the kill command is
    // responsible for removing it, so a stale-but-discoverable entry can be
    // inspected and cleaned up later.
    tracing::info!("worker exiting");
    Ok(())
}

/// Why the keep-alive loop ended — drives whether we signal cloudflared.
enum ReaderExit {
    ChildExited,
    Signal,
}

/// Shared context handed to each output-reader task.
#[derive(Clone)]
struct ReaderCtx {
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
                // Tee to tunnel.log (newline included by writeln).
                {
                    let mut f = ctx.log_writer.lock().await;
                    let _ = f.write_all(line.as_bytes()).await;
                    let _ = f.write_all(b"\n").await;
                    let _ = f.flush().await;
                }

                // First-URL-wins discovery.
                if !ctx.url_found.load(Ordering::Acquire) {
                    if let Some(url) = cloudflared::extract_url(&line) {
                        if !ctx.url_found.swap(true, Ordering::AcqRel) {
                            tracing::info!(%url, "discovered tunnel URL");
                            if let Err(e) = publish_url(&ctx, url) {
                                tracing::error!(%e, "failed to record tunnel URL");
                            }
                        }
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

/// Write the discovered `url` (and the tunnel pid, if known) onto the registry
/// entry for `ctx.name`, then save atomically.
fn publish_url(ctx: &ReaderCtx, url: String) -> Result<()> {
    let mut registry = Registry::load(&ctx.state)?;
    if let Some(svc) = registry.find_mut(&ctx.name) {
        svc.public_url = Some(url.clone());
        if svc.tunnel_pid.is_none() {
            svc.tunnel_pid = ctx.tunnel_pid;
        }
    } else {
        tracing::warn!(
            "service {} vanished from registry before URL could be recorded",
            ctx.name
        );
    }
    registry.save(&ctx.state)?;
    Ok(())
}

/// Initialise `tracing` to append to `worker.log` at the `info` level.
///
/// Subscribers are global, so this is a fire-once setup. If a subscriber was
/// already installed (e.g. by a test harness) we ignore the error.
fn init_tracing(worker_log: &PathBuf) {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(worker_log)
    else {
        return;
    };

    let filter = EnvFilter::try_new("info").unwrap_or_else(|_| EnvFilter::new("info"));

    let result = fmt()
        .with_env_filter(filter)
        .with_writer(file)
        .with_ansi(false)
        .try_init();

    if let Err(e) = result {
        // A subscriber is already installed; not fatal for the worker.
        eprintln!("tracing already initialized: {e}");
    }
}
