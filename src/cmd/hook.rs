//! The HOOK command.
//!
//! `ft hook` runs an ft-owned webhook receiver/inspector origin (see
//! `hook_server`) behind a cloudflared Quick Tunnel and registers the result
//! like any other service. The default background flow mirrors
//! START/PROXY/RUN's reserve-entry → spawn-worker → poll-for-URL shape; the
//! worker binds the origin itself on `127.0.0.1:<port>` (fail-fast on a bind
//! error, like a static worker), so success is "URL published" — no separate
//! origin probe is needed.
//!
//! Unlike RUN there is no child command, and unlike PROXY the port is ft's
//! own (it must be FREE, not already listening): a hook origin is bound by
//! ft, exactly like the static server.
//!
//! The foreground flow below duplicates the shared foreground machinery from
//! `cmd/start.rs` (`run_foreground_inner`) instead of extending it — that
//! file is outside this area's allowed paths, and the repo's frozen-core
//! rule says duplication with "keep the two in sync" comments beats touching
//! shared files (the same trade START/PROXY/RUN already make for
//! `last_reason`/`last_line` and the poll loop). Keep in sync with
//! `cmd/start.rs::run_foreground_inner` if its teardown order changes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

use crate::cloudflared;
use crate::error::Result;
use crate::hook_server::{self, HookLog};
use crate::model::{Registry, Service, ServiceKind};
use crate::name;
use crate::output;
use crate::port;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;

/// Reload cadence while waiting for the worker to publish the public URL.
/// Mirrors START/PROXY/RUN's poll loop (whose helpers are private to
/// `cmd/start.rs`).
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Upper bound on how long the parent will wait for the tunnel URL.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// Most bytes read from a log when surfacing a start-failure reason. Logs can
/// grow large; only the trailing window is examined (the first, partial line
/// after a mid-file seek is skipped).
const LAST_REASON_CAP: u64 = 16 * 1024;
/// Upper bound on draining in-flight requests on Ctrl-C before we abort the
/// server task, so a stuck request can't hang the foreground command.
/// Mirrors `cmd/start.rs`'s foreground drain bound.
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

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
    // rejection leaves zero state, like every other command's pre-flight.
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
/// the worker dies first).
///
/// Mirrors `cmd::start::run_background`/`cmd::proxy::run_background`
/// shape-for-shape; the scaffolding is duplicated rather than shared because
/// the static flow's helpers stay private to `cmd/start.rs` (frozen for this
/// area); keep the four in sync.
async fn run_background(port: u16, name: Option<String>, keep: u16) -> Result<()> {
    let state = StateDir::new()?;

    // --- cloudflared ------------------------------------------------------
    // Looked up BEFORE reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up (same ordering as
    // START/PROXY/RUN).
    cloudflared::ensure_installed()?;

    state.ensure()?;

    // --- Reserve name + id + entry atomically -----------------------------
    // Same contract as START/PROXY/RUN's reservation, including the M1
    // protection that comes free: `worker_pid: 0` + a fresh `created_at` puts
    // the entry inside `model::START_GRACE`, so a concurrent `ft kill` /
    // `ft prune` refuses to reap it during the reserve→spawn→record window
    // below (do NOT add any pid-0 staleness handling of our own —
    // `Service::start_in_progress` owns it). Every exit of ours resolves the
    // window quickly: spawn failure, worker death, and the URL timeout below
    // all remove the entry by id, which bypasses the grace guard.
    let (id, name) = Registry::update(&state, |reg| -> Result<(u64, String)> {
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            // Default matches the foreground hook flow (`hook-{port}` in
            // [`run_foreground`]) so both modes of `ft hook` produce the same
            // name for the same port, mirroring the proxy-{port}/run-{port}
            // convention.
            None => name::unique_name(reg, &format!("hook-{port}")),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Hook,
            // A hook serves no directory: its records live in the service
            // state dir (requests.json), not in a served tree.
            dir: None,
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            command_pid: None, // Run-only field; a hook spawns no command
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground: false,
        });
        Ok((id, name))
    })??;

    // --- Spawn worker -----------------------------------------------------
    // `dir: None` spawns a directory-less worker carrying `--keep`; the
    // HOOK arm in the worker binds the origin and opens the request store.
    let worker_pid = match spawn::spawn_hook_worker(id, &name, port, keep) {
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

    // --- Poll for the tunnel URL (fail-fast on worker death) --------------
    // Same mtime-gated loop as START/PROXY/RUN (the worker rewrites
    // registry.json only when it discovers the URL or self-removes).
    let registry_path = state.registry_path();
    let mut last_mtime = std::fs::metadata(&registry_path)
        .and_then(|m| m.modified())
        .ok();
    let deadline = Instant::now() + POLL_TIMEOUT;
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
                return fail_start(&state, id, &name, worker_pid).await;
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                // Unlike RUN, no extra origin probe: the worker bound the
                // hook origin before spawning cloudflared (fail-fast on a
                // bind error), so a published URL already implies an origin.
                output::print_started(&svc);
                return Ok(());
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — reap any survivors, surface
                // the reason inline (the entry is removed below, so we can't
                // send the user to `ft logs` afterwards), then fail fast.
                return fail_start(&state, id, &name, worker_pid).await;
            }
            Some(None) => {
                // Our entry vanished — a concurrent `ft kill` removed it, or
                // the worker self-removed on its own failure. Tear the worker
                // down and bail now instead of polling the full 30s with a
                // live, orphaned worker that nothing in the registry points
                // at.
                return fail_start(&state, id, &name, worker_pid).await;
            }
            // Some(Some(svc)) still starting, or None (unchanged registry):
            // poll again.
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out. The worker + cloudflared may still be alive and the entry is
    // still active, so tear them down (the group kill reaches the worker's
    // children) before bailing.
    proc::shutdown_process_group(worker_pid).await;
    if let Err(cleanup_err) = Registry::update(&state, |reg| {
        reg.remove(id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after URL timeout");
    }
    let reason = last_reason(&state, &name);
    bail!("timed out waiting for the tunnel URL{reason}")
}

/// Tear the just-started service down and fail: shared by the poll loop's
/// fail-fast arms (worker death, vanished entry). Duplicated from
/// `cmd/run.rs`'s frozen-core split; keep in sync.
async fn fail_start(state: &StateDir, id: u64, name: &str, worker_pid: u32) -> Result<()> {
    proc::shutdown_process_group(worker_pid).await;
    if let Err(cleanup_err) = Registry::update(state, |reg| {
        reg.remove(id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after worker death");
    }
    let reason = last_reason(state, name);
    bail!("worker for '{name}' exited before the tunnel came up{reason}")
}

/// Best-effort last non-empty log line to surface in a start-failure message.
/// Checks `tunnel.log` first (cloudflared's own output, where errors usually
/// appear), then `worker.log`. Duplicated from `cmd/start.rs`/`cmd/proxy.rs`
/// (where they are private) per the frozen-core split; keep the copies in
/// sync.
fn last_reason(state: &StateDir, name: &str) -> String {
    let pick = [state.tunnel_log(name), state.worker_log(name)]
        .into_iter()
        .find_map(|p| last_line(&p));
    match pick {
        Some(line) => format!(":\n  {line}"),
        None => String::new(),
    }
}

/// The last non-empty line of `path`, reading at most `LAST_REASON_CAP`
/// trailing bytes so a chatty cloudflared cannot make a start-failure message
/// slurp megabytes into memory. Duplicated from `cmd/start.rs`; see
/// [`last_reason`].
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

/// RAII guard that removes a reserved registry entry on drop. Duplicated from
/// `cmd/start.rs` (private there) per the frozen-core split — the foreground
/// flow has early-`?`/panic exits between reserve and teardown, and every one
/// of them must release the entry. Keep in sync.
struct EntryGuard {
    state: StateDir,
    id: u64,
}

impl Drop for EntryGuard {
    fn drop(&mut self) {
        if let Err(e) = Registry::update(&self.state, |reg| {
            reg.remove(self.id);
        }) {
            // Runs on every foreground exit path including panics, so a failed
            // cleanup must be visible (the entry would otherwise leak silently
            // until a later `ft prune`). tracing is sync-safe inside Drop.
            tracing::warn!(%e, id = self.id, "failed to clean up foreground registry entry on drop");
        }
    }
}

/// Why the foreground keep-alive loop ended. A hook foreground has no command
/// child, so unlike `cmd/start.rs`'s enum there is no `CommandExited` arm.
enum ReaderExit {
    ChildExited,
    Signal,
}

/// Foreground flow: run the hook origin and tunnel in this process and block
/// until cloudflared exits, Ctrl-C is received, or (Unix) SIGTERM arrives.
///
/// Duplicated from `cmd/start.rs::run_foreground_inner` (frozen-core split —
/// see the module docs); hook-specific differences: the kind is always
/// [`ServiceKind::Hook`], the origin is the hook server (records requests
/// into the service's request store), and there is no command child to own.
async fn run_foreground(port: u16, name: Option<String>, keep: u16) -> Result<()> {
    use crate::static_server;

    let state = StateDir::new()?;
    state.ensure()?;

    cloudflared::ensure_installed()?;

    // --- Reserve a registry entry (cross-platform) -------------------------
    // Mirrors `run_background`'s reservation, but marks this as a FOREGROUND
    // service whose worker_pid is THIS process. That makes `ft ls/detail/
    // logs/open` see the foreground tunnel on every platform — notably
    // Windows, where foreground is the only practical mode.
    let (id, name) = Registry::update(&state, |reg| -> Result<(u64, String)> {
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            // Default matches the background hook flow (`hook-{port}` in
            // [`run_background`]) so both modes of `ft hook` produce the same
            // name for the same port.
            None => name::unique_name(reg, &format!("hook-{port}")),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Hook,
            dir: None,
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid: std::process::id(),
            tunnel_pid: None,
            command_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground: true,
        });
        Ok((id, name))
    })??;

    // From here, every exit path must release the reserved entry (see
    // [`EntryGuard`]).
    let _entry = EntryGuard {
        state: state.clone(),
        id,
    };

    // Tee cloudflared output to tunnel.log so `ft logs <name>` works for
    // foreground tunnels (which otherwise only print to the terminal).
    let tunnel_log = state.tunnel_log(&name);
    let log_writer = Arc::new(Mutex::new(
        crate::fsutil::open_private_append_async(&tunnel_log)
            .await
            .with_context(|| format!("opening tunnel log {}", tunnel_log.display()))?,
    ));

    // Install the SIGTERM handler (Unix) BEFORE spawning the server +
    // cloudflared: if it fails the `?` returns with only the (guard-protected)
    // entry to clean up — no orphaned server task or cloudflared child is left
    // behind.
    #[cfg(unix)]
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    // The origin: ft's own hook server in THIS process. `serve` binds
    // 127.0.0.1:<port> (loopback-only, pre-flighted for freeness above) and
    // installs its own Ctrl-C drain; the JoinHandle is kept so the drain can
    // be bounded below.
    let hook_log = open_hook_log(&state, &name, keep)?;
    let router = hook_server::router(hook_log);
    let mut server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "hook server exited with error");
        }
    });

    let mut child = match cloudflared::spawn(port, PathBuf::new()) {
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
    // publish the public URL on first discovery (so `ft open`/`ft detail`
    // work too). Duplicated from `cmd/start.rs::drain_and_announce`
    // (frozen-core split); keep in sync.
    let found = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    if let Some(out) = child.stdout.take() {
        tasks.push(tokio::spawn(drain_and_announce(
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
        tasks.push(tokio::spawn(drain_and_announce(
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

    // If cloudflared may still be alive, shut it down and reap it to avoid a
    // transient zombie. On ChildExited the select's wait() already reaped it.
    // The signal/escalation/reap sequence is shared with the detached worker
    // via [`cloudflared::shutdown`].
    if matches!(exit_reason, ReaderExit::Signal) {
        cloudflared::shutdown(tunnel_pid, &mut child).await;
    }

    for task in tasks {
        task.abort();
    }

    // `serve`'s own Ctrl-C handler has already begun draining on Ctrl-C; bound
    // it so a stuck request can't hang the foreground command, falling back
    // to abort.
    match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut server_handle).await {
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(
                "hook server did not drain within {:?}, aborting",
                SERVER_SHUTDOWN_TIMEOUT
            );
            server_handle.abort();
        }
    }

    // The `_entry` guard removes our registry entry on return (every exit
    // path).
    Ok(())
}

/// Read `lines` to EOF, mirror each line to stdout AND `tunnel.log`, and
/// publish the first discovered Quick Tunnel URL onto the registry entry
/// (printing the foreground success banner at the same time). Duplicated from
/// `cmd/start.rs::drain_and_announce` (frozen-core split — the helper is
/// private there and `cmd/start.rs` is outside this area's allowed paths);
/// keep in sync.
#[allow(clippy::too_many_arguments)]
async fn drain_and_announce<R>(
    mut lines: tokio::io::Lines<R>,
    found: Arc<AtomicBool>,
    name: String,
    port: u16,
    state: StateDir,
    id: u64,
    tunnel_pid: Option<u32>,
    log_writer: Arc<tokio::sync::Mutex<tokio::fs::File>>,
) where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncWriteExt;
    while let Ok(Some(line)) = lines.next_line().await {
        println!("{line}");
        {
            let mut f = log_writer.lock().await;
            let _ = f.write_all(line.as_bytes()).await;
            let _ = f.write_all(b"\n").await;
            let _ = f.flush().await;
        }
        if !found.load(Ordering::Acquire)
            && let Some(url) = cloudflared::extract_url(&line)
            && !found.swap(true, Ordering::AcqRel)
        {
            println!();
            println!("Started {name}");
            println!();
            println!("Local:   http://127.0.0.1:{port}");
            println!("Public:  {url}");
            println!();
            if let Err(e) = Registry::update(&state, |reg| {
                if let Some(svc) = reg.find_mut(&id.to_string()) {
                    svc.public_url = Some(url.clone());
                    if svc.tunnel_pid.is_none() {
                        svc.tunnel_pid = tunnel_pid;
                    }
                }
            }) {
                tracing::error!(%e, "failed to record foreground tunnel URL");
            }
        }
    }
}
