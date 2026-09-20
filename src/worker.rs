//! The detached worker (`ft run-worker ...`): fronts the service's local
//! origin with a cloudflared Quick Tunnel child, records the tunnel URL on
//! the registry entry, and stays alive until cloudflared exits, a signal
//! arrives, or the origin ends. What to front comes from the reserved
//! registry entry's `kind`, not the CLI args; cloudflared connects lazily,
//! so a dead upstream is not a start-time failure here. All registry writes
//! go through [`Registry::update`] (an exclusive flock), so the parent's
//! writes and ours never clobber each other.

use std::ffi::OsString;
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
use crate::server::drop_server::{self, DropStore};
use crate::server::hook_server;
use crate::server::hook_server::HookLog;
use crate::server::static_server;
use crate::state::StateDir;

const REGISTRY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const REGISTRY_LOOKUP_INTERVAL: Duration = Duration::from_millis(100);
/// Drain bound; a stuck request aborts the server task so it can't hang the
/// worker.
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Run the worker to completion. `dir` is the served/upload directory
/// ([`crate::spawn::PROXY_DIR_SENTINEL`] for the directory-less kinds).
pub async fn run(
    id: u64,
    name: String,
    dir: PathBuf,
    port: u16,
    command: Vec<OsString>,
    keep: Option<u16>,
    max_size: Option<u64>,
) -> Result<()> {
    // Defense in depth against direct invocation (spawn_worker sets
    // FT_WORKER_TOKEN): presence check only — the real checks re-run below.
    if std::env::var_os("FT_WORKER_TOKEN")
        .map(|v| v.is_empty())
        .unwrap_or(true)
    {
        anyhow::bail!(
            "run-worker is an internal command spawned by `ft`'s start/proxy flows; invoke those instead"
        );
    }

    // Windows: a KILL_ON_JOB_CLOSE Job Object — worker exit kills the whole
    // tree (the PR_SET_PDEATHSIG equivalent; no-op on Unix).
    #[cfg(windows)]
    let _job_guard = crate::proc::create_kill_on_close_job();

    let state = StateDir::new()?;
    let worker_log = state.worker_log(&name);
    let server_log = state.server_log(&name);
    let tunnel_log = state.tunnel_log(&name);

    // Port 0 would bind a kernel-assigned port that mismatches the reserved
    // one (Static) or front an invalid upstream (Proxy).
    if port == 0 {
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("port 0 is reserved; the worker needs an explicit port");
    }

    // The parent's save may not have landed yet — poll for the entry by id,
    // not name: a reused name would bind us to the wrong (fresh) service.
    let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_TIMEOUT;
    if !await_entry(&state, id, deadline).await? {
        // Dying worker mustn't leave a stale entry; clear ours by id.
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("registry entry for service id={id} never appeared");
    }

    // A miss means the entry vanished between probe and load (a concurrent
    // `ft kill`) — exit rather than serve an untracked tunnel.
    let Some(entry) = Registry::load(&state)?.find(&id.to_string()).cloned() else {
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("registry entry for service id={id} vanished before start");
    };
    let kind = entry.kind;
    // Flags persisted on the entry, not argv — argv would duplicate state and
    // leak the token into `ps`.
    let static_flags = entry.static_flags;

    // server.log opens only for a Static worker (only it emits tower_http
    // traces); pre-kind exits fail to stderr → worker.log via the parent.
    init_tracing(
        &worker_log,
        (kind == ServiceKind::Static).then_some(server_log.as_path()),
    );

    tracing::info!("worker starting: id={id} name={name:?} port={port}");

    // Static and Drop: re-run the START directory checks before binding a
    // public tunnel — refusal is UNCONDITIONAL (non-interactive, no `--yes`).
    let dir = match kind {
        ServiceKind::Proxy => {
            tracing::info!("proxy worker: fronting existing upstream http://127.0.0.1:{port}");
            None
        }
        ServiceKind::Run => {
            tracing::info!("run worker: will spawn the command as the local origin");
            None
        }
        ServiceKind::Hook => {
            tracing::info!("hook worker: recording requests behind the tunnel");
            None
        }
        ServiceKind::Drop => {
            // Reads AND writes its directory — checked like Static, refusal
            // unconditional (a writable target is strictly more dangerous).
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
                    "refusing to use sensitive directory {} as a drop bucket \
                     from a detached worker (uploads write into it)",
                    dir.display()
                );
            }
            tracing::info!(dir = %dir.display(), "drop worker: accepting uploads into directory");
            Some(dir)
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

    // Self-register the pid: if the parent died between spawn and record,
    // `ft kill` can still reach us.
    Registry::update(&state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string())
            && svc.worker_pid == 0
        {
            svc.worker_pid = std::process::id();
        }
    })?;

    // Static/Hook/Drop bind now (fail-fast on a taken port) so the parent's
    // poll detects a dead worker instead of waiting out a 502-ing tunnel.
    let (shutdown_tx, mut server_handle) = match kind {
        ServiceKind::Static => {
            let dir =
                dir.expect("static worker resolved its directory above (kind match invariant)");
            let listener = bind_loopback_fail_fast(&state, id, port).await?;
            tracing::info!("static server bound on 127.0.0.1:{port}");

            let router = static_server::router_with(dir.to_path_buf(), static_flags);
            serve_origin(router, listener)
        }
        ServiceKind::Hook => {
            let keep = usize::from(keep.unwrap_or(hook_server::DEFAULT_KEEP));
            let hook_log = match open_request_store(&state, &name, keep) {
                Ok(log) => log,
                Err(e) => {
                    let _ = Registry::update(&state, |reg| {
                        reg.remove(id);
                    });
                    return Err(e);
                }
            };
            let listener = bind_loopback_fail_fast(&state, id, port).await?;
            tracing::info!("hook origin bound on 127.0.0.1:{port}");

            serve_origin(hook_server::router(hook_log), listener)
        }
        ServiceKind::Drop => {
            let dir =
                dir.expect("drop worker resolved its upload target above (kind match invariant)");
            let token = match open_drop_token(&state, &name) {
                Ok(token) => token,
                Err(e) => {
                    let _ = Registry::update(&state, |reg| {
                        reg.remove(id);
                    });
                    return Err(e);
                }
            };
            let max_upload = max_size.unwrap_or(drop_server::DEFAULT_MAX_SIZE);
            let store = match DropStore::open(&dir, token, max_upload, drop_server::MAX_TOTAL_STORE)
            {
                Ok(store) => store,
                Err(e) => {
                    let _ = Registry::update(&state, |reg| {
                        reg.remove(id);
                    });
                    return Err(e)
                        .with_context(|| format!("opening the drop bucket at {}", dir.display()));
                }
            };
            let listener = bind_loopback_fail_fast(&state, id, port).await?;
            tracing::info!("drop origin bound on 127.0.0.1:{port}");

            serve_origin(drop_server::router(store), listener)
        }
        ServiceKind::Proxy | ServiceKind::Run => no_server(),
    };

    if let Err(e) = cloudflared::ensure_installed() {
        tracing::error!(%e, "cloudflared unavailable");
        stop_server(kind, shutdown_tx, &mut server_handle).await;
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        return Err(e);
    }

    // Run only: open the log sink BEFORE the child (a failure must not
    // orphan a running command); teed to worker.log, nothing extracted.
    let command_log_writer = match kind {
        ServiceKind::Run => match crate::fsutil::open_private_append_async(&worker_log).await {
            Ok(f) => Some(Arc::new(Mutex::new(f))),
            Err(e) => {
                stop_server(kind, shutdown_tx, &mut server_handle).await;
                let _ = Registry::update(&state, |reg| {
                    reg.remove(id);
                });
                return Err(e)
                    .with_context(|| format!("opening worker log {}", worker_log.display()));
            }
        },
        _ => None,
    };

    // Run only: the child leads its own process group, so the exit paths tear
    // the WHOLE subtree down via killpg without ever signalling this worker's
    // group (cloudflared lives there).
    let (command_pid, mut command_monitor, command_out) = match kind {
        ServiceKind::Run => match crate::proc::spawn_command_child(&command, port) {
            Ok(mut c) => {
                let pid = c.id();
                let stdout = c.stdout.take();
                let stderr = c.stderr.take();
                let monitor = crate::proc::spawn_wait_monitor(c);
                (pid, monitor, (stdout, stderr))
            }
            Err(e) => {
                tracing::error!(%e, "failed to spawn the command");
                stop_server(kind, shutdown_tx, &mut server_handle).await;
                let _ = Registry::update(&state, |reg| {
                    reg.remove(id);
                });
                return Err(e);
            }
        },
        _ => (
            None,
            crate::proc::command_monitor_placeholder(),
            (None, None),
        ),
    };

    // Best-effort, NOT `?`: with the child already running, a registry-write
    // failure must not abort the worker and orphan it.
    if let Some(pid) = command_pid
        && let Err(e) = Registry::update(&state, |reg| {
            if let Some(svc) = reg.find_mut(&id.to_string()) {
                svc.command_pid = Some(pid);
            }
        })
    {
        tracing::warn!(%e, id, "failed to record the command pid on the registry entry");
    }

    let (command_stdout, command_stderr) = command_out;
    let mut reader_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if let Some(command_log_writer) = command_log_writer {
        if let Some(out) = command_stdout {
            reader_tasks.push(tokio::spawn(pipe_command_stream(
                BufReader::new(out),
                command_log_writer.clone(),
            )));
        }
        if let Some(err) = command_stderr {
            reader_tasks.push(tokio::spawn(pipe_command_stream(
                BufReader::new(err),
                command_log_writer,
            )));
        }
    }

    // Installed BEFORE cloudflared::spawn: no post-spawn failure may leave a
    // live tunnel with no handler installed. Windows: ctrl_c() in the select.
    #[cfg(unix)]
    let (mut sig_term, mut sig_int) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::terminate()).context("installing SIGTERM handler")?,
            signal(SignalKind::interrupt()).context("installing SIGINT handler")?,
        )
    };

    let mut child = match cloudflared::spawn(port) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%e, "failed to spawn cloudflared");
            // The command must not outlive a tunnel that never came to be.
            crate::proc::shutdown_child_command(command_pid, &mut command_monitor).await;
            stop_server(kind, shutdown_tx, &mut server_handle).await;
            let _ = Registry::update(&state, |reg| {
                reg.remove(id);
            });
            return Err(e);
        }
    };
    let tunnel_pid = child.id();
    tracing::info!(?tunnel_pid, "cloudflared tunnel spawned");

    let url_found = Arc::new(AtomicBool::new(false));
    let log_writer = match crate::fsutil::open_private_append_async(&tunnel_log).await {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            // cloudflared is ALREADY live, so a bare `?` would orphan it: on
            // macOS neither PDEATHSIG nor the Job Object reaps it, and with
            // no URL published, prune can never find the orphaned tunnel.
            tracing::error!(%e, "failed to open the tunnel log");
            cloudflared::shutdown(tunnel_pid, &mut child).await;
            crate::proc::shutdown_child_command(command_pid, &mut command_monitor).await;
            stop_server(kind, shutdown_tx, &mut server_handle).await;
            let _ = Registry::update(&state, |reg| {
                reg.remove(id);
            });
            return Err(e).with_context(|| format!("opening tunnel log {}", tunnel_log.display()));
        }
    };

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

    if let Some(out) = stdout {
        reader_tasks.push(tokio::spawn(pipe_stream(BufReader::new(out), ctx.clone())));
    }
    if let Some(err) = stderr {
        reader_tasks.push(tokio::spawn(pipe_stream(BufReader::new(err), ctx.clone())));
    }

    // Keep alive until cloudflared exits, the origin ends, the command child
    // exits, or a signal arrives (placeholders: see no_server/stop_server).
    #[cfg(unix)]
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
                    Ok(Ok(())) => tracing::info!("local origin task ended"),
                    Ok(Err(e)) => tracing::error!(%e, "local origin task failed"),
                    Err(e) => tracing::error!(%e, "local origin task panicked"),
                }
                ReaderExit::ServerEnded
            }
            _ = &mut command_monitor => {
                tracing::info!("command child exited");
                ReaderExit::CommandExited
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
                    Ok(Ok(())) => tracing::info!("local origin task ended"),
                    Ok(Err(e)) => tracing::error!(%e, "local origin task failed"),
                    Err(e) => tracing::error!(%e, "local origin task panicked"),
                }
                ReaderExit::ServerEnded
            }
            _ = &mut command_monitor => {
                tracing::info!("command child exited");
                ReaderExit::CommandExited
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C, shutting down");
                ReaderExit::Signal
            }
        };
        teardown_on_exit(exit_reason, tunnel_pid, &mut child).await;
    }

    // The command child must NEVER outlive the worker's tunnel ownership —
    // also on the cloudflared-exited path. Group-wide; no-op for other kinds.
    crate::proc::shutdown_child_command(command_pid, &mut command_monitor).await;

    // Abort AND await: abort only schedules cancellation at the next .await —
    // a reader mid-`publish_url` could race the entry's removal by teardown.
    for task in reader_tasks {
        task.abort();
        let _ = task.await;
    }

    stop_server(kind, shutdown_tx, &mut server_handle).await;

    tracing::info!("worker exiting");
    Ok(())
}

/// Why the keep-alive loop ended — drives cloudflared teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReaderExit {
    /// cloudflared itself exited; it was reaped by the select's `wait()`.
    ChildExited,
    /// The local origin server task ended (static, hook, and drop workers).
    ServerEnded,
    /// The Run command child exited — the origin is gone; follow it down.
    CommandExited,
    /// SIGTERM/SIGINT (or Ctrl-C on Windows) arrived.
    Signal,
}

/// Bind fail-fast: a failure removes the reserved entry so the parent's poll
/// sees it instead of waiting out the timeout.
async fn bind_loopback_fail_fast(
    state: &StateDir,
    id: u64,
    port: u16,
) -> Result<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => Ok(l),
        Err(e) => {
            let _ = Registry::update(state, |reg| {
                reg.remove(id);
            });
            Err(e).with_context(|| format!("failed to bind 127.0.0.1:{port}"))
        }
    }
}

/// Fails at startup: a store that cannot live on disk would 500 every
/// webhook once the tunnel is up.
fn open_request_store(
    state: &StateDir,
    name: &str,
    keep: usize,
) -> Result<Arc<std::sync::Mutex<HookLog>>> {
    state.ensure_service_dir(name)?;
    let path = state.service_dir(name).join(hook_server::REQUESTS_FILENAME);
    // load()'s Err is fatal here — never rename over an intact store.
    let log = HookLog::load(path.clone(), keep)
        .with_context(|| format!("opening hook request store {}", path.display()))?;
    Ok(Arc::new(std::sync::Mutex::new(log)))
}

/// Missing or unreadable token is fatal: without it the origin cannot
/// authenticate an upload, so it must never serve a public tunnel.
fn open_drop_token(state: &StateDir, name: &str) -> Result<String> {
    let dir = state.service_dir(name);
    match drop_server::read_token(&dir) {
        Ok(Some(token)) if !token.is_empty() => Ok(token),
        Ok(_) => anyhow::bail!(
            "the drop token file is missing or empty in {} — cannot serve an \
             unauthenticated upload endpoint",
            dir.display()
        ),
        Err(e) => Err(e).with_context(|| format!("reading the drop token in {}", dir.display())),
    }
}

/// Serve task + graceful-shutdown channel: firing the sender drains
/// in-flight requests instead of aborting mid-flight.
fn serve_origin(
    router: axum::Router,
    listener: tokio::net::TcpListener,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<crate::error::Result<()>>,
) {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        static_server::serve_on(router, listener, async {
            let _ = shutdown_rx.await;
        })
        .await
    });
    (shutdown_tx, server_handle)
}

/// `ChildExited` already reaped cloudflared in the select; every other
/// reason must signal.
fn teardown_should_signal(exit_reason: &ReaderExit) -> bool {
    !matches!(exit_reason, ReaderExit::ChildExited)
}

/// Never-completing placeholder for the server slot (no server of one's
/// own); stop_server aborts it instead of burning the drain timeout.
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

/// Static/Hook/Drop: graceful drain bounded by [`SERVER_SHUTDOWN_TIMEOUT`]
/// (abort on overrun). Proxy/Run: the placeholder is aborted outright.
async fn stop_server(
    kind: ServiceKind,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    server_handle: &mut tokio::task::JoinHandle<crate::error::Result<()>>,
) {
    if !matches!(
        kind,
        ServiceKind::Static | ServiceKind::Hook | ServiceKind::Drop
    ) {
        server_handle.abort();
        return;
    }
    let _ = shutdown_tx.send(());
    match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut *server_handle).await {
        Ok(Ok(Ok(()))) => tracing::info!("local origin drained and exited"),
        Ok(Ok(Err(e))) => tracing::error!(%e, "local origin task failed during shutdown"),
        Ok(Err(e)) => tracing::error!(%e, "local origin task panicked during shutdown"),
        Err(_) => {
            tracing::warn!(
                "local origin did not drain within {:?}, aborting",
                SERVER_SHUTDOWN_TIMEOUT
            );
            server_handle.abort();
        }
    }
}

/// Read-only poll — an update() here would contend with the parent's
/// pid-record and every concurrent `ft` command.
async fn await_entry(state: &StateDir, id: u64, deadline: std::time::Instant) -> Result<bool> {
    while std::time::Instant::now() < deadline {
        if Registry::load(state)?.find(&id.to_string()).is_some() {
            return Ok(true);
        }
        tokio::time::sleep(REGISTRY_LOOKUP_INTERVAL).await;
    }
    Ok(false)
}

/// Shut cloudflared down if it may still be alive (shared with the
/// foreground flow).
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

#[derive(Clone)]
struct ReaderCtx {
    /// Registry key — unique & stable, unlike `name` (reusable after a kill).
    id: u64,
    /// Display only — used in log messages, never as a registry key.
    name: String,
    state: StateDir,
    tunnel_pid: Option<u32>,
    url_found: Arc<AtomicBool>,
    log_writer: Arc<Mutex<tokio::fs::File>>,
}

/// Tee cloudflared output to tunnel.log; publish the first URL found.
async fn pipe_stream<R>(reader: BufReader<R>, ctx: ReaderCtx)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = reader.lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                // One lock take + write per line: append mode makes each
                // write atomic, and no flush stops the two readers contending.
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

/// Tee the command's output into worker.log (nothing is extracted from it).
async fn pipe_command_stream<R>(reader: BufReader<R>, log_writer: Arc<Mutex<tokio::fs::File>>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = reader.lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let mut buf = line.as_bytes().to_vec();
                buf.push(b'\n');
                let mut f = log_writer.lock().await;
                let _ = f.write_all(&buf).await;
            }
            Ok(None) => break, // EOF
            Err(e) => {
                tracing::warn!(%e, "error reading command output stream");
                break;
            }
        }
    }
}

/// By id, under the exclusive lock — a stale worker must not clobber a
/// re-used name's entry.
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

/// Fire-once init; tower_http traces -> server.log (Static only), worker
/// traces -> worker.log.
fn init_tracing(worker_log: &Path, server_log: Option<&Path>) {
    use std::sync::Mutex;
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    // Both filters are hardcoded — EnvFilter::new never consults RUST_LOG,
    // on purpose: at the tower_http=info floor no per-request spans (all
    // debug) reach the append-mode, never-rotated server.log, so it records
    // no request URIs; raising the floor is a source change, on purpose.
    let server_layer = server_log
        .and_then(|path| crate::fsutil::open_private_append(path).ok())
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

    /// Mirrors `dummy_service` in registry.rs.
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
            static_flags: crate::model::StaticFlags::default(),
            command_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
        }
    }

    /// Throwaway ctx — the log file is never written to here.
    async fn reader_ctx(state: StateDir, id: u64, tunnel_pid: Option<u32>) -> ReaderCtx {
        // ensure_service_dir creates the parent of tunnel.log so the open
        // below succeeds.
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

        // A different id + a one-interval deadline runs the body once before
        // timing out (a past deadline would skip it, making this vacuous).
        Registry::update(&state, |reg| {
            reg.services.push(seed_service(11, "alpha"));
        })
        .expect("seed");

        let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_INTERVAL;
        let found = await_entry(&state, 5, deadline).await.expect("no io error");
        assert!(!found);
    }

    #[tokio::test]
    async fn await_entry_finds_by_id_not_name() {
        let tmp = tempdir().expect("state dir");
        let state = StateDir::new_at(tmp.path().to_path_buf());
        state.ensure().expect("ensure state dir");

        Registry::update(&state, |reg| {
            reg.services.push(seed_service(11, "alpha"));
        })
        .expect("seed");

        let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_TIMEOUT;
        assert!(await_entry(&state, 11, deadline).await.expect("io"));
        let past = std::time::Instant::now();
        assert!(!await_entry(&state, 99, past).await.expect("io"));
    }

    #[test]
    fn teardown_should_signal_only_on_signal_or_server_ended() {
        assert!(!teardown_should_signal(&ReaderExit::ChildExited));
        assert!(teardown_should_signal(&ReaderExit::Signal));
        assert!(teardown_should_signal(&ReaderExit::ServerEnded));
        assert!(teardown_should_signal(&ReaderExit::CommandExited));
    }

    #[tokio::test]
    async fn stop_server_aborts_proxy_placeholder_without_waiting_out_the_timeout() {
        let (shutdown_tx, mut server_handle) = no_server();
        let started = std::time::Instant::now();
        stop_server(ServiceKind::Proxy, shutdown_tx, &mut server_handle).await;

        let err = server_handle
            .await
            .expect_err("proxy placeholder must be aborted, still pending");
        assert!(err.is_cancelled());
        assert!(started.elapsed() < SERVER_SHUTDOWN_TIMEOUT);
    }

    #[tokio::test]
    async fn stop_server_aborts_a_run_placeholder_without_waiting_out_the_timeout() {
        // A kind guard that forgot Run would add the full timeout to every
        // run exit.
        let (shutdown_tx, mut server_handle) = no_server();
        let started = std::time::Instant::now();
        stop_server(ServiceKind::Run, shutdown_tx, &mut server_handle).await;

        let err = server_handle
            .await
            .expect_err("run placeholder must be aborted, still pending");
        assert!(err.is_cancelled());
        assert!(started.elapsed() < SERVER_SHUTDOWN_TIMEOUT);
    }

    #[tokio::test]
    async fn stop_server_drains_a_hook_origin_like_a_static_one() {
        let tmp = tempdir().expect("tempdir");
        let store = crate::server::hook_server::HookLog::load(
            tmp.path().join("requests.json"),
            usize::from(crate::server::hook_server::DEFAULT_KEEP),
        )
        .expect("load");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral loopback listener");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, mut server_handle) = serve_origin(
            crate::server::hook_server::router(Arc::new(std::sync::Mutex::new(store))),
            listener,
        );
        let started = std::time::Instant::now();
        stop_server(ServiceKind::Hook, shutdown_tx, &mut server_handle).await;
        assert!(started.elapsed() < SERVER_SHUTDOWN_TIMEOUT);

        // The JoinHandle is deliberately NOT re-awaited: polling a completed
        // JoinHandle panics.
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "the hook origin must stop accepting after the drain"
        );
    }

    #[tokio::test]
    async fn stop_server_drains_a_drop_origin_like_a_static_one() {
        let tmp = tempdir().expect("tempdir");
        let store = crate::server::drop_server::DropStore::open(
            tmp.path(),
            "tok".to_string(),
            crate::server::drop_server::DEFAULT_MAX_SIZE,
            crate::server::drop_server::MAX_TOTAL_STORE,
        )
        .expect("open drop store");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral loopback listener");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown_tx, mut server_handle) =
            serve_origin(crate::server::drop_server::router(store), listener);
        let started = std::time::Instant::now();
        stop_server(ServiceKind::Drop, shutdown_tx, &mut server_handle).await;
        assert!(started.elapsed() < SERVER_SHUTDOWN_TIMEOUT);
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "the drop origin must stop accepting after the drain"
        );
    }
}
