//! The detached worker process.
//!
//! Invoked as `ft run-worker --id --name --dir --port`, this fronts the
//! service's local origin with a `cloudflared` Quick Tunnel child, discovers
//! the tunnel URL from cloudflared's output, records it on the registry entry,
//! and stays alive until cloudflared exits, a terminating signal arrives, or
//! (static services only) the server task ends.
//!
//! What to front is decided by the reserved registry entry's `kind`, not by
//! the CLI args: a `Static` worker re-runs the START flow's directory safety
//! checks, binds ft's own static server on `127.0.0.1` (fail-fast if the port
//! cannot be bound), and tunnels it; a `Proxy` worker runs no server of its
//! own — it points cloudflared straight at the operator's existing upstream
//! on `http://127.0.0.1:<port>`. cloudflared connects lazily, so a dead
//! upstream is deliberately NOT a start-time failure here (a friendly
//! pre-flight, if any, belongs to the CLI layer).
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
use crate::cmd::start::{is_sensitive_dir, resolve_dir};
use crate::error::Result;
use crate::model::{Registry, ServiceKind};
use crate::state::StateDir;
use crate::static_server;

/// How long to keep retrying the registry load looking for our entry.
const REGISTRY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const REGISTRY_LOOKUP_INTERVAL: Duration = Duration::from_millis(100);
/// Upper bound on how long we wait for in-flight requests to drain after
/// signalling graceful shutdown. If a request is stuck, we abort the server
/// task as a fallback so it can't hang the worker indefinitely.
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Run the worker to completion.
///
/// `dir` is the `--dir` CLI value: the served directory for `Static` services,
/// and [`crate::spawn::PROXY_DIR_SENTINEL`] for `Proxy` services (which have
/// no directory — clap rejects an empty `--dir` value, so the spawn path
/// passes that deliberately non-existent stand-in path; see the module docs
/// for why the kind comes from the reserved registry entry rather than the
/// CLI).
pub async fn run(id: u64, name: String, dir: PathBuf, port: u16) -> Result<()> {
    // Defense in depth against direct invocation: `run-worker` is an internal
    // command only ever launched by `spawn::spawn_worker`, which sets
    // `FT_WORKER_TOKEN`; reject anything without a non-empty value. This is a
    // presence check only — the load-bearing safety checks (resolve_dir /
    // is_sensitive_dir / port) are re-run below, inside this non-interactive
    // worker, so neither direct invocation NOR any future caller can bypass them.
    if std::env::var_os("FT_WORKER_TOKEN")
        .map(|v| v.is_empty())
        .unwrap_or(true)
    {
        anyhow::bail!(
            "run-worker is an internal command spawned by `ft`'s start/proxy flows; invoke those instead"
        );
    }

    // Windows: place ourselves in a Job Object with KILL_ON_JOB_CLOSE, held for
    // the lifetime of `run`. When the worker exits for any reason (graceful, ft
    // kill, OOM, crash) the OS closes the handle and kills the whole tree
    // (cloudflared) — the PR_SET_PDEATHSIG equivalent. On Unix this is a no-op
    // (Linux uses PR_SET_PDEATHSIG in cloudflared::spawn).
    #[cfg(windows)]
    let _job_guard = crate::proc::create_kill_on_close_job();

    let state = StateDir::new()?;
    let worker_log = state.worker_log(&name);
    let server_log = state.server_log(&name);
    let tunnel_log = state.tunnel_log(&name);

    init_tracing(&worker_log, &server_log);

    tracing::info!("worker starting: id={id} name={name:?} port={port}");

    // Kind-agnostic port guard. A `Static` worker would otherwise bind a
    // kernel-assigned port that mismatches the one the parent reserved and
    // advertised; a `Proxy` worker's port IS the operator's upstream, where 0
    // is never valid either.
    if port == 0 {
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("port 0 is reserved; the worker needs an explicit port");
    }

    // Recover our registry entry (parent race). The parent reserves the entry
    // before spawning us, but there is a window before the atomic save lands.
    // Look up by id, not name: if a stale worker is still draining while the
    // parent reuses this name for a new service, a name lookup would bind us to
    // the wrong entry. The id is unique and stable.
    let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_TIMEOUT;
    if !await_entry(&state, id, deadline).await? {
        // Dying worker mustn't leave a permanent stale entry; clear ours by id.
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("registry entry for service id={id} never appeared");
    }

    // What this worker fronts comes from the reserved entry — the parent wrote
    // the kind (and, for Static, the directory) before spawning us. A miss here
    // means the entry vanished between the probe and this load (a concurrent
    // `ft kill`): exit rather than serve an untracked tunnel.
    let Some(kind) = Registry::load(&state)?
        .find(&id.to_string())
        .map(|s| s.kind)
    else {
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("registry entry for service id={id} vanished before start");
    };

    // SEC-1 / ARCH-05 / CLI-1 (Static only): re-run the START flow's directory
    // safety checks here, inside the detached worker, *before* we bind a public
    // tunnel to the directory. `FT_WORKER_TOKEN` above is only a presence check
    // (defense in depth against direct `run-worker` invocation); it does not by
    // itself enforce anything. A worker is non-interactive, so a sensitive
    // directory is refused UNCONDITIONALLY — `--yes` cannot apply, and there is
    // no way to confirm. This closes the foot-gun where `FT_WORKER_TOKEN=x ft
    // run-worker --dir /etc` would publish `/etc` with zero confirmation.
    //
    // Proxy services skip these checks by construction: they publish no
    // directory at all — the tunnel fronts a port the operator chose to run.
    let dir = match kind {
        ServiceKind::Proxy => {
            tracing::info!("proxy worker: fronting existing upstream http://127.0.0.1:{port}");
            None
        }
        ServiceKind::Static => {
            let dir = match resolve_dir(&dir) {
                Ok(d) => d,
                Err(e) => {
                    let _ = Registry::update(&state, |reg| {
                        reg.remove(id);
                    });
                    return Err(e);
                }
            };
            if is_sensitive_dir(&dir) {
                let _ = Registry::update(&state, |reg| {
                    reg.remove(id);
                });
                anyhow::bail!(
                    "refusing to publish sensitive directory {} from a detached worker",
                    dir.display()
                );
            }
            tracing::info!(dir = %dir.display(), "static worker: serving directory");
            Some(dir)
        }
    };

    // Self-register our pid once (the parent records it normally, but if it died
    // between spawn and recording this keeps `ft kill` able to reach us). A
    // single locked write — the probe loop above was read-only.
    Registry::update(&state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string())
            && svc.worker_pid == 0
        {
            svc.worker_pid = std::process::id();
        }
    })?;

    // Local origin. Static: bind the listener now (fail-fast) — if the port is
    // taken, the worker exits immediately and the parent's poll detects the
    // dead worker instead of waiting out the full timeout with a dead tunnel
    // returning 502s. Proxy: no server of our own to bind or run.
    let (shutdown_tx, mut server_handle) = match dir.as_deref() {
        Some(dir) => {
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

            let router = static_server::router(dir.to_path_buf());

            // Graceful shutdown channel: on the teardown path we fire
            // `shutdown_tx`, which lets axum stop accepting and drain in-flight
            // requests instead of aborting the server task (and dropping the
            // requests) mid-flight.
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let server_handle = tokio::spawn(async move {
                static_server::serve_on(router, listener, async {
                    let _ = shutdown_rx.await;
                })
                .await
            });
            (shutdown_tx, server_handle)
        }
        None => no_server(),
    };

    // cloudflared
    if let Err(e) = cloudflared::ensure_installed() {
        tracing::error!(%e, "cloudflared unavailable");
        // Nothing is serving the tunnel yet; tear the local origin down
        // gracefully (it may already have accepted connections).
        stop_server(kind, shutdown_tx, &mut server_handle).await;
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
            stop_server(kind, shutdown_tx, &mut server_handle).await;
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
        crate::fsutil::open_private_append_async(&tunnel_log)
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
    // observed rather than silently lost. For a proxy worker the server slot
    // holds [`no_server`]'s never-completing placeholder, so the server arm
    // below can never fire — exactly the intent: the only local origin is the
    // operator's, which this worker does not own and cannot observe.
    //
    // The signal arms are platform-split: on Unix we install explicit
    // SIGTERM/SIGINT handlers (tokio::signal::unix); on Windows we fall back to
    // ctrl_c(). Both arms are reachable — the background worker runs on every
    // platform (Unix detaches via setsid, Windows via a Job Object).
    #[cfg(unix)]
    {
        let mut sig_term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
        teardown_on_exit(exit_reason, tunnel_pid, &mut child).await;
    }
    #[cfg(not(unix))]
    {
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
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C, shutting down");
                ReaderExit::Signal
            }
        };
        teardown_on_exit(exit_reason, tunnel_pid, &mut child).await;
    }

    // Abort the reader tasks AND await them. Aborting alone only schedules
    // cancellation at the next `.await`; if a reader is mid-way through the
    // synchronous `publish_url` -> `Registry::update` (fs2 lock_exclusive wait)
    // it keeps running until that call returns, so a late publish_url could
    // race the registry entry being removed by teardown. Awaiting the handle
    // guarantees the task is actually gone (and surfaces any panic) before we
    // proceed to drain the server.
    for task in reader_tasks {
        task.abort();
        let _ = task.await;
    }

    // Drain in-flight requests (Static only — a proxy worker's server slot is
    // the [`no_server`] placeholder, which `stop_server` aborts outright): fire
    // the shutdown signal and let axum finish what it's serving, with a bounded
    // timeout so a stuck request can't hang the worker. If the drain doesn't
    // complete in time, abort as a fallback.
    stop_server(kind, shutdown_tx, &mut server_handle).await;

    tracing::info!("worker exiting");
    Ok(())
}

/// Why the keep-alive loop ended — drives cloudflared teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReaderExit {
    ChildExited,
    ServerEnded,
    Signal,
}

/// Pure decision: should teardown actively signal/reap cloudflared for this
/// exit reason? On `ChildExited` the select's `wait()` already reaped the child,
/// so there is nothing to do. On `Signal`/`ServerEnded` cloudflared may still be
/// alive and must be torn down. Extracted so the branching is unit-testable
/// without a real child process.
fn teardown_should_signal(exit_reason: &ReaderExit) -> bool {
    matches!(exit_reason, ReaderExit::Signal | ReaderExit::ServerEnded)
}

/// The local-origin stand-in for proxy services, which run no static server of
/// their own — the worker fronts the operator's existing upstream directly.
///
/// The keep-alive `select!` in [`run`] is written against a server task handle,
/// so a proxy worker parks a never-completing task in that slot (the server arm
/// can then never fire) together with a shutdown sender whose receiver is
/// dropped, which makes sending on it a harmless no-op. [`stop_server`] aborts
/// the placeholder instead of waiting out [`SERVER_SHUTDOWN_TIMEOUT`] on
/// nothing.
fn no_server() -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<crate::error::Result<()>>,
) {
    let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    (
        shutdown_tx,
        tokio::spawn(std::future::pending::<crate::error::Result<()>>()),
    )
}

/// Stop the worker's local origin, if it runs one.
///
/// `Static`: fire the graceful-shutdown signal and let axum finish what it's
/// serving, bounded by [`SERVER_SHUTDOWN_TIMEOUT`] so a stuck request cannot
/// hang the worker; on overrun the task is aborted as a fallback. `Proxy`:
/// there is no server — the handle is [`no_server`]'s placeholder, which never
/// completes — so it is aborted outright rather than burning the timeout.
async fn stop_server(
    kind: ServiceKind,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    server_handle: &mut tokio::task::JoinHandle<crate::error::Result<()>>,
) {
    if kind == ServiceKind::Proxy {
        server_handle.abort();
        return;
    }
    let _ = shutdown_tx.send(());
    match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut *server_handle).await {
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
}

/// Poll the registry read-only until our entry (by id) appears, or `deadline`
/// passes. Takes NO advisory lock and does NOT rewrite the registry — an earlier
/// revision used `Registry::update` here, which contended with the parent's
/// pid-record and every concurrent `ft` command by rewriting all of
/// registry.json every 100ms. Returns `false` if the entry never landed.
async fn await_entry(state: &StateDir, id: u64, deadline: std::time::Instant) -> Result<bool> {
    while std::time::Instant::now() < deadline {
        if Registry::load(state)?.find(&id.to_string()).is_some() {
            return Ok(true);
        }
        tokio::time::sleep(REGISTRY_LOOKUP_INTERVAL).await;
    }
    Ok(false)
}

/// If cloudflared may still be alive, shut it down and reap it — the actual
/// signal/escalation/reap sequence lives in [`cloudflared::shutdown`], shared
/// with the foreground flow. On `ChildExited` the select's `wait()` already
/// reaped it, so nothing to do.
async fn teardown_on_exit(
    exit_reason: ReaderExit,
    tunnel_pid: Option<u32>,
    child: &mut tokio::process::Child,
) {
    if !teardown_should_signal(&exit_reason) {
        return;
    }
    cloudflared::shutdown(tunnel_pid, child).await;
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
                // Coalesce the line + newline into one buffer and take the lock
                // once for a single write_all. Append mode already makes each
                // write_all atomic, so the per-line `flush().await` is dropped
                // from the hot path (the OS flushes on close; tokio::fs also
                // buffers). This cuts three awaits-under-lock down to one and
                // removes the per-line fsync-flush that contended the two
                // reader tasks (stdout + stderr).
                let mut buf = line.as_bytes().to_vec();
                buf.push(b'\n');
                {
                    let mut f = ctx.log_writer.lock().await;
                    let _ = f.write_all(&buf).await;
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
    Registry::update(&ctx.state, move |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string()) {
            svc.public_url = Some(url);
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
    use std::sync::Mutex;
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    // tower_http request traces -> server.log; everything else -> worker.log.
    // Each layer is Option-wrapped so a failure to open one log file just drops
    // that sink rather than aborting tracing setup. Mode 0600 on Unix (server.log
    // can carry request URIs); plain create on Windows via the cross-platform
    // helper.
    //
    // PERF-3: gate the request layer at `info` (request span open/close) rather
    // than `trace` (one event per proxied request body chunk). server.log is
    // opened once in append mode and never rotated, so a `trace` filter would
    // grow it without bound on a busy tunnel. `info` keeps the per-request span
    // without the per-event flood; raise the level via `RUST_LOG=tower_http=trace`
    // when debugging a specific request.
    let server_layer = crate::fsutil::open_private_append(server_log)
        .ok()
        .map(|f| {
            fmt::layer()
                .with_writer(Mutex::new(f))
                .with_ansi(false)
                .with_filter(EnvFilter::new("tower_http=info"))
        });

    let worker_layer = crate::fsutil::open_private_append(worker_log)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Registry, Service};
    use std::path::PathBuf;
    use tempfile::tempdir;

    /// A minimal service for seeding a registry. Mirrors `dummy_service` in
    /// registry.rs.
    fn seed_service(id: u64, name: &str) -> Service {
        Service {
            id,
            name: name.to_string(),
            kind: ServiceKind::Static,
            dir: Some(PathBuf::from("/tmp/dir")),
            port: 1234,
            local_url: "http://127.0.0.1:1234".to_string(),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
        }
    }

    /// A throwaway reader context: `publish_url` only reads `id`, `name`,
    /// `state`, and `tunnel_pid`, so `log_writer`/`url_found` are best-effort.
    /// The log file is opened from a std handle (we never write to it in these
    /// tests) so construction is synchronous and non-flaky.
    async fn reader_ctx(state: StateDir, id: u64, tunnel_pid: Option<u32>) -> ReaderCtx {
        // ensure_service_dir creates the parent of tunnel.log so the open below
        // succeeds; publish_url never writes to it.
        state
            .ensure_service_dir("test-svc")
            .expect("ensure service dir");
        let log_path = state.tunnel_log("test-svc");
        let log = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await
            .expect("open tunnel.log");
        ReaderCtx {
            id,
            name: "svc".to_string(),
            state,
            tunnel_pid,
            url_found: Arc::new(AtomicBool::new(false)),
            log_writer: Arc::new(Mutex::new(log)),
        }
    }

    #[tokio::test]
    async fn publish_url_records_url_and_pid_on_existing_entry() {
        let tmp = tempdir().expect("state dir");
        let state = StateDir::new_at(tmp.path().to_path_buf());
        state.ensure().expect("ensure state dir");

        // Seed an entry for id=7 with no public_url and no tunnel_pid.
        Registry::update(&state, |reg| {
            reg.services.push(seed_service(7, "svc"));
        })
        .expect("seed");

        let ctx = reader_ctx(state.clone(), 7, Some(4242)).await;
        publish_url(&ctx, "https://abc.trycloudflare.com".to_string())
            .expect("publish_url succeeds");

        let reg = Registry::load(&state).expect("load");
        let svc = reg.find("7").expect("entry present");
        assert_eq!(
            svc.public_url.as_deref(),
            Some("https://abc.trycloudflare.com")
        );
        assert_eq!(svc.tunnel_pid, Some(4242));
    }

    #[tokio::test]
    async fn publish_url_does_not_clobber_existing_tunnel_pid() {
        let tmp = tempdir().expect("state dir");
        let state = StateDir::new_at(tmp.path().to_path_buf());
        state.ensure().expect("ensure state dir");

        // Pre-existing tunnel_pid must NOT be overwritten (race between two
        // readers: only the first wins).
        Registry::update(&state, |reg| {
            let mut svc = seed_service(9, "svc");
            svc.tunnel_pid = Some(1111);
            reg.services.push(svc);
        })
        .expect("seed");

        let ctx = reader_ctx(state.clone(), 9, Some(2222)).await;
        publish_url(&ctx, "https://xyz.trycloudflare.com".to_string())
            .expect("publish_url succeeds");

        let reg = Registry::load(&state).expect("load");
        let svc = reg.find("9").expect("entry present");
        assert_eq!(svc.tunnel_pid, Some(1111)); // unchanged
        assert_eq!(
            svc.public_url.as_deref(),
            Some("https://xyz.trycloudflare.com")
        );
    }

    #[tokio::test]
    async fn publish_url_is_a_noop_for_a_vanished_id() {
        // A vanished id (e.g. parent already removed our entry) must NOT panic
        // and must NOT create a stray entry — publish_url only mutates in the
        // Some(svc) branch.
        let tmp = tempdir().expect("state dir");
        let state = StateDir::new_at(tmp.path().to_path_buf());
        state.ensure().expect("ensure state dir");

        let ctx = reader_ctx(state.clone(), 404, Some(99)).await;
        publish_url(&ctx, "https://ghost.trycloudflare.com".to_string())
            .expect("publish_url still succeeds (no error)");

        let reg = Registry::load(&state).expect("load");
        assert!(reg.find("404").is_none(), "no stray entry created");
        assert!(reg.services.is_empty());
    }

    #[tokio::test]
    async fn await_entry_returns_true_when_entry_present() {
        let tmp = tempdir().expect("state dir");
        let state = StateDir::new_at(tmp.path().to_path_buf());
        state.ensure().expect("ensure state dir");

        Registry::update(&state, |reg| {
            reg.services.push(seed_service(5, "svc"));
        })
        .expect("seed");

        let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_TIMEOUT;
        let found = await_entry(&state, 5, deadline).await.expect("no io error");
        assert!(found);
    }

    #[tokio::test]
    async fn await_entry_returns_false_on_timeout_when_absent() {
        let tmp = tempdir().expect("state dir");
        let state = StateDir::new_at(tmp.path().to_path_buf());
        state.ensure().expect("ensure state dir");

        // Seed a *different* id so the loop actually loads the registry and
        // searches — an empty registry would make "not found" trivially true
        // without ever exercising the poll path.
        Registry::update(&state, |reg| {
            reg.services.push(seed_service(11, "alpha"));
        })
        .expect("seed");

        // A deadline one poll-interval in the future: the loop runs its body
        // once (load -> search -> sleep), finds id 5 absent, then times out
        // and returns false. (A past deadline would skip the body entirely,
        // making the test vacuous.)
        let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_INTERVAL;
        let found = await_entry(&state, 5, deadline).await.expect("no io error");
        assert!(!found);
    }

    #[tokio::test]
    async fn await_entry_finds_by_id_not_name() {
        // If a name is reused for a fresh service while a stale worker drains,
        // the id lookup must bind to OUR entry, not a name collision.
        let tmp = tempdir().expect("state dir");
        let state = StateDir::new_at(tmp.path().to_path_buf());
        state.ensure().expect("ensure state dir");

        Registry::update(&state, |reg| {
            reg.services.push(seed_service(11, "alpha"));
        })
        .expect("seed");

        let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_TIMEOUT;
        // Looking up the right id finds it; a different id with the same name
        // must NOT be found.
        assert!(await_entry(&state, 11, deadline).await.expect("io"));
        let past = std::time::Instant::now();
        assert!(!await_entry(&state, 99, past).await.expect("io"));
    }

    #[test]
    fn teardown_should_signal_only_on_signal_or_server_ended() {
        // ChildExited: the select already reaped cloudflared, so teardown is a
        // no-op.
        assert!(!teardown_should_signal(&ReaderExit::ChildExited));
        // Signal / ServerEnded: cloudflared may still be alive -> must signal.
        assert!(teardown_should_signal(&ReaderExit::Signal));
        assert!(teardown_should_signal(&ReaderExit::ServerEnded));
    }

    #[tokio::test]
    async fn stop_server_aborts_proxy_placeholder_without_waiting_out_the_timeout() {
        // A proxy worker owns no server: stop_server must abort the parked
        // placeholder immediately. Waiting out SERVER_SHUTDOWN_TIMEOUT here
        // would hang every proxy worker teardown by that much.
        let (shutdown_tx, mut server_handle) = no_server();
        let started = std::time::Instant::now();
        stop_server(ServiceKind::Proxy, shutdown_tx, &mut server_handle).await;

        // The placeholder is gone: awaiting it resolves right away as
        // cancelled (it would otherwise stay pending forever), and the whole
        // call stayed well under the drain bound.
        let err = server_handle
            .await
            .expect_err("proxy placeholder must be aborted, still pending");
        assert!(err.is_cancelled());
        assert!(started.elapsed() < SERVER_SHUTDOWN_TIMEOUT);
    }
}
