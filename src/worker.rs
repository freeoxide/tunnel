//! The detached worker process.
//!
//! Invoked as `ft run-worker --id --name --dir --port [--keep N]
//! [--max-size N] [-- <command>]`, this fronts the service's local origin
//! with a `cloudflared` Quick Tunnel child, discovers the tunnel URL from
//! cloudflared's output, records it on the registry entry, and stays alive
//! until cloudflared exits, a terminating signal arrives, or (static, hook,
//! and drop services) the server task ends.
//!
//! What to front is decided by the reserved registry entry's `kind`, not the
//! CLI args: `Static` re-runs the START directory checks and binds ft's own
//! static server (fail-fast on bind); `Proxy` runs no server, pointing
//! cloudflared straight at the operator's upstream; `Run` spawns the
//! operator's command as a group-isolated child of THIS process (see
//! `proc::spawn_command_child`) so exit teardown takes the whole command
//! subtree down; `Hook` binds ft's own webhook receiver, recording requests
//! to the service's store; `Drop` binds ft's own upload receiver after
//! re-running the directory checks and reading the access token from the
//! service's private token file (fail-fast on either). cloudflared connects
//! lazily, so a dead upstream is deliberately NOT a start-time failure here
//! (a friendly pre-flight belongs to the CLI layer). All registry writes go
//! through [`Registry::update`] (an exclusive flock), so the parent's writes
//! and ours never clobber each other.

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

/// How long to keep retrying the registry load looking for our entry.
const REGISTRY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const REGISTRY_LOOKUP_INTERVAL: Duration = Duration::from_millis(100);
/// Upper bound on how long we wait for in-flight requests to drain after
/// signalling graceful shutdown. If a request is stuck, we abort the server
/// task as a fallback so it can't hang the worker indefinitely.
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Run the worker to completion.
///
/// `dir` is the `--dir` CLI value: the served directory for `Static`, the
/// upload target for `Drop`, and [`crate::spawn::PROXY_DIR_SENTINEL`] for the
/// directory-less kinds (see the module docs for why the kind comes from the
/// registry entry, not the CLI). `command` is the Run worker's child command,
/// `keep` the Hook retention, `max_size` the Drop per-upload cap — empty/`None`
/// for every other kind.
pub async fn run(
    id: u64,
    name: String,
    dir: PathBuf,
    port: u16,
    command: Vec<OsString>,
    keep: Option<u16>,
    max_size: Option<u64>,
) -> Result<()> {
    // Defense in depth against direct invocation: `run-worker` is only ever
    // launched by `spawn::spawn_worker`, which sets `FT_WORKER_TOKEN`. A
    // presence check only — the load-bearing safety checks (resolve_dir /
    // is_sensitive_dir / port) are re-run below.
    if std::env::var_os("FT_WORKER_TOKEN")
        .map(|v| v.is_empty())
        .unwrap_or(true)
    {
        anyhow::bail!(
            "run-worker is an internal command spawned by `ft`'s start/proxy flows; invoke those instead"
        );
    }

    // Windows: a KILL_ON_JOB_CLOSE Job Object held for the lifetime of `run`
    // — when the worker exits for any reason, the OS kills the whole tree.
    // The PR_SET_PDEATHSIG equivalent; no-op on Unix.
    #[cfg(windows)]
    let _job_guard = crate::proc::create_kill_on_close_job();

    let state = StateDir::new()?;
    let worker_log = state.worker_log(&name);
    let server_log = state.server_log(&name);
    let tunnel_log = state.tunnel_log(&name);

    // Kind-agnostic port guard: 0 would bind a kernel-assigned port that
    // mismatches the reserved one (Static) or front an invalid upstream
    // (Proxy).
    if port == 0 {
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("port 0 is reserved; the worker needs an explicit port");
    }

    // Recover our registry entry (the parent's atomic save may not have
    // landed yet). Look up by id, not name: a name reused for a fresh service
    // while a stale worker drains would bind us to the wrong entry.
    let deadline = std::time::Instant::now() + REGISTRY_LOOKUP_TIMEOUT;
    if !await_entry(&state, id, deadline).await? {
        // Dying worker mustn't leave a permanent stale entry; clear ours by id.
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("registry entry for service id={id} never appeared");
    }

    // What this worker fronts comes from the reserved entry. A miss here
    // means the entry vanished between the probe and this load (a concurrent
    // `ft kill`): exit rather than serve an untracked tunnel.
    let Some(entry) = Registry::load(&state)?.find(&id.to_string()).cloned() else {
        let _ = Registry::update(&state, |reg| {
            reg.remove(id);
        });
        anyhow::bail!("registry entry for service id={id} vanished before start");
    };
    let kind = entry.kind;
    // The static-origin flags were persisted on the reserved entry by the
    // parent, so the worker re-applies exactly what the operator asked for
    // (no flag rides the argv — that would duplicate state and leak the token
    // into `ps`). Meaningless for non-Static kinds, which never read it.
    let static_flags = entry.static_flags;

    // Tracing sits AFTER the kind read: the server.log sink receives
    // tower_http request traces, which only a Static worker can emit —
    // opening it for a Proxy worker would create a permanently empty file.
    // The pre-kind exits fail to stderr, which the parent redirects into
    // worker.log anyway.
    init_tracing(
        &worker_log,
        (kind == ServiceKind::Static).then_some(server_log.as_path()),
    );

    tracing::info!("worker starting: id={id} name={name:?} port={port}");

    // Static and Drop: re-run the START flow's directory safety checks here,
    // inside the detached worker, *before* binding a public tunnel to the
    // directory. A worker is non-interactive, so a sensitive directory is
    // refused UNCONDITIONALLY (`--yes` cannot apply) — this closes the
    // foot-gun where `FT_WORKER_TOKEN=x ft run-worker --dir /etc` would
    // publish `/etc` with zero confirmation. Proxy/Run/Hook publish no
    // directory (the tunnel fronts a port/origin the operator chose).
    let dir = match kind {
        ServiceKind::Proxy => {
            tracing::info!("proxy worker: fronting existing upstream http://127.0.0.1:{port}");
            None
        }
        ServiceKind::Run => {
            // The origin is the command this worker is about to spawn — no
            // directory to resolve or confirm.
            tracing::info!("run worker: will spawn the command as the local origin");
            None
        }
        ServiceKind::Hook => {
            // ft's own webhook receiver — no directory to resolve or confirm.
            tracing::info!("hook worker: recording requests behind the tunnel");
            None
        }
        ServiceKind::Drop => {
            // An ft-owned origin like static/hook, but it READS AND WRITES a
            // directory: the checks run exactly like a Static worker's, with
            // the sensitive-directory refusal unconditional (a writable
            // target is strictly more dangerous than a read-only publish).
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

    // Self-register our pid once (the parent records it normally, but if it
    // died between spawn and record this keeps `ft kill` able to reach us).
    Registry::update(&state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string())
            && svc.worker_pid == 0
        {
            svc.worker_pid = std::process::id();
        }
    })?;

    // Local origin. Static, Hook, and Drop: bind the listener now (fail-fast
    // on a taken port) so the parent's poll detects a dead worker instead of
    // waiting out the full timeout with a 502-ing tunnel. Proxy and Run run
    // no server of their own.
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
            // Open the request store before binding so a broken service dir
            // fails the worker immediately instead of 500-ing every webhook
            // once the tunnel is up.
            let keep = usize::from(keep.unwrap_or(hook_server::DEFAULT_KEEP));
            let hook_log = match open_request_store(&state, &name, keep) {
                Ok(log) => log,
                Err(e) => {
                    // Dying worker mustn't leave a permanent stale entry.
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
            // Read the access token from the service's private token file
            // (written by the parent between reserve and spawn) and open the
            // bucket — both before binding, so a missing token or an
            // unresolvable bucket fails the worker immediately instead of
            // serving a tunnel that cannot authenticate uploads.
            let dir =
                dir.expect("drop worker resolved its upload target above (kind match invariant)");
            let token = match open_drop_token(&state, &name) {
                Ok(token) => token,
                Err(e) => {
                    // Dying worker mustn't leave a permanent stale entry.
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
                    // Dying worker mustn't leave a permanent stale entry.
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

    // Run only: open the command's log sink BEFORE spawning the child, so a
    // failure can never orphan an already-running command. The output is teed
    // into worker.log (the log `ft logs` already reads); nothing is extracted
    // from these lines — tunnel URLs come only from cloudflared's streams.
    let command_log_writer = match kind {
        ServiceKind::Run => match crate::fsutil::open_private_append_async(&worker_log).await {
            Ok(f) => Some(Arc::new(Mutex::new(f))),
            Err(e) => {
                // Dying worker mustn't leave a permanent stale entry; nothing
                // is spawned yet (the sink opens BEFORE the command child on
                // purpose), so teardown is just the server slot + the entry.
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

    // Run only: spawn the operator's command as THIS worker's child, before
    // the tunnel exists. The child leads its own process group, so the exit
    // paths below tear the WHOLE command subtree down (child + grandchildren
    // like vite) via `killpg`, without ever signalling this worker's group
    // (cloudflared lives there, torn down separately). The monitor owns the
    // handle; the worker keeps the bare pid.
    let (command_pid, mut command_monitor, command_out) = match kind {
        ServiceKind::Run => match crate::proc::spawn_command_child(&command, port) {
            Ok(mut c) => {
                // A freshly spawned, unreaped child always reports its pid.
                let pid = c.id();
                let stdout = c.stdout.take();
                let stderr = c.stderr.take();
                let monitor = crate::proc::spawn_wait_monitor(c);
                (pid, monitor, (stdout, stderr))
            }
            Err(e) => {
                tracing::error!(%e, "failed to spawn the command");
                stop_server(kind, shutdown_tx, &mut server_handle).await;
                // Dying worker mustn't leave a permanent stale entry.
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

    // Record the command child's pid under the lock (Run only). Best-effort,
    // NOT `?`: with the child already running, a registry-write failure must
    // not abort the worker and orphan it — the exit paths still tear
    // everything down.
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
            // The command child must not outlive a tunnel that never came to
            // be; the monitor handles the teardown (graceful group SIGTERM →
            // KILL on Unix, terminate + job close on Windows).
            crate::proc::shutdown_child_command(command_pid, &mut command_monitor).await;
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
    let log_writer = match crate::fsutil::open_private_append_async(&tunnel_log).await {
        Ok(f) => Arc::new(Mutex::new(f)),
        Err(e) => {
            // cloudflared is ALREADY live here (unlike the spawn-failure arm
            // above), so a bare `?` would orphan it: on macOS neither
            // PR_SET_PDEATHSIG (Linux) nor the Job Object (Windows) exists
            // to reap it, and publish_url never ran, so tunnel_pid is
            // unpublished and prune/sanitize could never find the orphaned
            // public tunnel either. Tear everything down in the normal-exit
            // order: cloudflared, the command child's group, the server
            // slot, the registry entry.
            tracing::error!(%e, "failed to open the tunnel log");
            cloudflared::shutdown(tunnel_pid, &mut child).await;
            crate::proc::shutdown_child_command(command_pid, &mut command_monitor).await;
            stop_server(kind, shutdown_tx, &mut server_handle).await;
            // Dying worker mustn't leave a permanent stale entry.
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

    // Keep alive until cloudflared exits, the server task ends, the command
    // child (Run only) exits, or we're signalled. Polling server_handle
    // ensures a post-bind serve failure is observed. Proxy workers hold
    // [`no_server`]'s never-completing placeholder in the server slot (the
    // only origin is the operator's, which this worker cannot observe); Run
    // workers hold the spawned child's monitor in the command slot (its exit
    // is the origin dying — tear the tunnel down, not serve 502s forever).
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

    // The command child must NEVER outlive the worker's ownership of the
    // tunnel — including the cloudflared-exited path, where cloudflared is
    // already reaped but a Run worker's command may still be running. Covers
    // the command's whole process GROUP; a no-op for other kinds.
    crate::proc::shutdown_child_command(command_pid, &mut command_monitor).await;

    // Abort the reader tasks AND await them: aborting only schedules
    // cancellation at the next `.await`, and a reader mid-way through the
    // synchronous `publish_url` -> `Registry::update` (fs2 lock wait) could
    // otherwise race the entry being removed by teardown. Awaiting proves
    // the task is gone (and surfaces panics).
    for task in reader_tasks {
        task.abort();
        let _ = task.await;
    }

    // Drain in-flight requests (Static/Hook/Drop; a proxy/run worker's
    // placeholder is aborted outright): bounded so a stuck request cannot
    // hang the worker, aborting on overrun.
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
    /// The Run worker's command child exited — the origin is gone, so the
    /// worker follows it down instead of serving a 502-ing tunnel.
    CommandExited,
    /// SIGTERM/SIGINT (or Ctrl-C on Windows) arrived.
    Signal,
}

/// Bind the local origin's listener on `127.0.0.1:port`, fail-fast: a bind
/// failure removes the reserved entry and kills the worker, so the parent's
/// poll sees it instead of waiting out the full timeout. Loopback-only by
/// construction — only the local cloudflared process can reach this server.
async fn bind_loopback_fail_fast(
    state: &StateDir,
    id: u64,
    port: u16,
) -> Result<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => Ok(l),
        Err(e) => {
            // Dying worker mustn't leave a permanent stale entry.
            let _ = Registry::update(state, |reg| {
                reg.remove(id);
            });
            Err(e).with_context(|| format!("failed to bind 127.0.0.1:{port}"))
        }
    }
}

/// Open a hook service's request store (re-ensuring its service dir): a
/// store that cannot live on disk would 500 every webhook once the tunnel is
/// up, so the failure belongs at startup.
fn open_request_store(
    state: &StateDir,
    name: &str,
    keep: usize,
) -> Result<Arc<std::sync::Mutex<HookLog>>> {
    state.ensure_service_dir(name)?;
    let path = state.service_dir(name).join(hook_server::REQUESTS_FILENAME);
    // load fails fast on a non-NotFound read error (the store may be intact
    // behind it) — surface the disk problem at startup, never rename over it.
    let log = HookLog::load(path.clone(), keep)
        .with_context(|| format!("opening hook request store {}", path.display()))?;
    Ok(Arc::new(std::sync::Mutex::new(log)))
}

/// Read a drop service's access token back from its private token file (the
/// parent wrote it between reserve and spawn). A MISSING file or a read
/// ERROR is fatal: without the token the origin cannot authenticate a single
/// upload, so it must never serve a public tunnel — fail fast at startup.
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

/// Spawn an origin's serve task with its graceful-shutdown channel: firing
/// the sender later lets axum stop accepting and drain in-flight requests
/// instead of aborting mid-flight. Shared by the static/hook/drop arms.
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

/// Pure decision: should teardown actively signal/reap cloudflared for this
/// exit reason? On `ChildExited` the select's `wait()` already reaped it.
/// Extracted so the branching is unit-testable without a real child.
fn teardown_should_signal(exit_reason: &ReaderExit) -> bool {
    !matches!(exit_reason, ReaderExit::ChildExited)
}

/// The local-origin stand-in for workers that run no server of their own
/// (proxy fronts the operator's upstream; run's origin is the spawned
/// command): a never-completing task in the `select!`'s server slot (the
/// server arm can never fire) plus a shutdown sender whose dropped receiver
/// makes sending a no-op. [`stop_server`] aborts the placeholder instead of
/// waiting out [`SERVER_SHUTDOWN_TIMEOUT`] on nothing.
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

/// Stop the worker's local origin, if it runs one. `Static`/`Hook`/`Drop`:
/// fire the graceful-shutdown signal and drain, bounded by
/// [`SERVER_SHUTDOWN_TIMEOUT`] (abort on overrun). `Proxy`/`Run`: no server —
/// the [`no_server`] placeholder is aborted outright rather than burning the
/// timeout (a run's origin is torn down by
/// [`crate::proc::shutdown_child_command`], not this slot).
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

/// Poll the registry read-only until our entry (by id) appears, or `deadline`
/// passes. Takes NO advisory lock and does NOT rewrite the registry — an
/// `Registry::update` here would contend with the parent's pid-record and
/// every concurrent `ft` command. Returns `false` if the entry never landed.
async fn await_entry(state: &StateDir, id: u64, deadline: std::time::Instant) -> Result<bool> {
    while std::time::Instant::now() < deadline {
        if Registry::load(state)?.find(&id.to_string()).is_some() {
            return Ok(true);
        }
        tokio::time::sleep(REGISTRY_LOOKUP_INTERVAL).await;
    }
    Ok(false)
}

/// If cloudflared may still be alive, shut it down and reap it via
/// [`cloudflared::shutdown`] (shared with the foreground flow).
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
                // Coalesce line + newline into one buffer and take the lock
                // once for a single write_all: append mode already makes each
                // write atomic, so no per-line flush is needed on the hot
                // path (which also stops the two reader tasks contending).
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

/// Read a command child's output stream line by line, teeing each line into
/// worker.log so `ft logs` shows the origin's own output. Nothing is
/// extracted from these lines — tunnel URLs come only from cloudflared.
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
            Ok(None) => break, // EOF — the child closed this stream
            Err(e) => {
                tracing::warn!(%e, "error reading command output stream");
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

/// Initialise `tracing`: the tower_http request-trace layer writes to
/// `server.log` (only a Static worker has a server to trace, so others pass
/// `None` and no file is created); worker/ft traces go to `worker.log`.
/// Fire-once; a no-op if a subscriber is installed.
fn init_tracing(worker_log: &Path, server_log: Option<&Path>) {
    use std::sync::Mutex;
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    // tower_http request traces -> server.log; everything else -> worker.log.
    // Each layer is Option-wrapped so a failure to open one log file just
    // drops that sink; 0600 on Unix (the sink that would carry request URIs
    // if its filter were ever raised).
    //
    // PERF-3: both filters are hardcoded literals — `EnvFilter::new` never
    // consults `RUST_LOG`, so there is deliberately no environment knob. At
    // the `tower_http=info` floor the per-request spans/events (all debug)
    // are filtered out, so server.log receives no request URIs at all — only
    // the error-level "response failed" event can pass, which carries no
    // URL. A lower floor would feed per-request spans into an append-mode,
    // never-rotated file, so raising the level is a source change, on
    // purpose.
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
            static_flags: crate::model::StaticFlags::default(),
            command_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
        }
    }

    /// A throwaway reader context: `publish_url` only reads `id`, `name`,
    /// `state`, and `tunnel_pid`; the log file is never written to here.
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

        // Pre-existing tunnel_pid must NOT be overwritten (two-reader race:
        // only the first wins).
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
        // A vanished id must not panic and must not create a stray entry.
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

        // Seed a *different* id so the loop actually loads and searches; a
        // deadline one poll-interval out runs the body once (load -> search
        // -> sleep) before timing out (a past deadline would skip the body
        // entirely, making the test vacuous).
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
        // A name reused while a stale worker drains must not confuse the id
        // lookup.
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
        // ChildExited: the select already reaped cloudflared.
        assert!(!teardown_should_signal(&ReaderExit::ChildExited));
        // Everything else: cloudflared may still be alive -> must signal. (A
        // dead command child is itself a teardown trigger: the origin is
        // gone, so the tunnel must follow it down.)
        assert!(teardown_should_signal(&ReaderExit::Signal));
        assert!(teardown_should_signal(&ReaderExit::ServerEnded));
        assert!(teardown_should_signal(&ReaderExit::CommandExited));
    }

    #[tokio::test]
    async fn stop_server_aborts_proxy_placeholder_without_waiting_out_the_timeout() {
        // A proxy worker owns no server: the placeholder must be aborted
        // immediately, not waited out.
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
        // Same contract, Run flavour: a kind guard that forgot Run would
        // silently add the full drain timeout to every run worker's exit.
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
        // A hook worker runs an ft-owned origin in-process, so its teardown
        // must DRAIN (an in-flight recording finishes writing) rather than
        // abort — pins the Hook arm of the kind split.
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

        // The origin is gone for real: the drained listener no longer
        // accepts connections. (The JoinHandle is deliberately NOT awaited
        // again — stop_server's bounded await may already have driven the
        // task to completion, and polling a completed JoinHandle panics.)
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "the hook origin must stop accepting after the drain"
        );
    }

    #[tokio::test]
    async fn stop_server_drains_a_drop_origin_like_a_static_one() {
        // Same contract, Drop flavour: DRAIN so an in-flight upload finishes
        // writing — pins the Drop arm of the kind split.
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
