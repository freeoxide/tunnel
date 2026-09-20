//! The START command.
//!
//! Background: reserve an entry, spawn a detached worker owning the static
//! server + cloudflared, poll for the public URL (fail fast if the worker
//! dies first). `--foreground`: server + tunnel run in-process until
//! cloudflared exits or Ctrl-C. The foreground machinery is shared with the
//! proxy flow (`dir: None`) and the run flow (`command: Some`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};

use super::{POLL_INTERVAL, POLL_TIMEOUT};
use crate::cloudflared;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind, StaticFlags};
use crate::name;
use crate::output;
use crate::port;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;

/// Most bytes read from a log when surfacing a start-failure reason; only
/// the trailing window is examined.
const LAST_REASON_CAP: u64 = 16 * 1024;
/// Bound on draining in-flight requests on Ctrl-C before the server task is
/// aborted, so a stuck request can't hang the foreground. Shared with hook.
pub(crate) const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Entry point for the START command. `dir` defaults to `.`; an empty
/// `--token` value is refused (empty secret = lockout or "no auth" misread).
pub async fn run(
    dir: Option<PathBuf>,
    name: Option<String>,
    port: Option<u16>,
    foreground: bool,
    yes: bool,
    static_flags: StaticFlags,
) -> Result<()> {
    let dir = dir.unwrap_or_else(|| PathBuf::from("."));
    let dir = resolve_dir(&dir)?;
    // Guard the most foot-gun case: publishing $HOME or the filesystem root
    // to the public internet (dotfiles are already refused by the server).
    confirm_sensitive(&dir, yes)?;
    // An empty (or whitespace-only) --token is a typo, not a configuration;
    // the stored value stays verbatim (all readers share the registry value).
    if let Some(token) = &static_flags.token {
        ensure!(
            !token.trim().is_empty(),
            "--token must be a non-empty secret"
        );
    }

    if foreground {
        run_foreground_with_options(dir.as_path(), name, port, static_flags).await
    } else {
        run_background(&dir, name, port, static_flags).await
    }
}

/// Refuse — or prompt y/N (default No) — when serving a sensitive directory.
/// Non-interactive runs must pass `yes`.
fn confirm_sensitive(dir: &Path, yes: bool) -> Result<()> {
    if !is_sensitive_dir(dir) {
        return Ok(());
    }
    use std::io::{IsTerminal, Write};
    eprintln!(
        "[!] Publishing '{}' to the PUBLIC internet via a Cloudflare Quick Tunnel.",
        dir.display()
    );
    eprintln!("    Anyone with the URL can read its contents. Dotfiles are refused by default.");

    if yes {
        eprintln!("    (--yes given; proceeding)");
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "refusing to publish a sensitive directory ({}) non-interactively; \
             re-run with --yes to confirm",
            dir.display()
        );
    }
    eprint!("    Proceed? [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    if !line.trim().eq_ignore_ascii_case("y") {
        bail!("aborted");
    }
    Ok(())
}

/// True for directories whose wholesale public exposure is almost certainly a
/// mistake: the filesystem root and well-known system dirs; `$HOME` or any of
/// its ancestors; anything overlapping ft's own state tree (registry.json,
/// logs, hook records, drop-token files — none dotfile-hidden). Both sides
/// are canonicalised so a symlink alias cannot slip past; unresolvable paths
/// fail CLOSED.
pub(crate) fn is_sensitive_dir(dir: &Path) -> bool {
    let Ok(dir) = std::fs::canonicalize(dir) else {
        return true; // fail-closed: can't resolve it -> refuse to publish silently.
    };

    // Entries are canonicalised so platform symlinks match (macOS /etc ->
    // /private/etc); non-existent entries (e.g. /proc on macOS) are skipped.
    const DENYLIST: &[&str] = &[
        "/", "/etc", "/root", "/var", "/home", "/Users", "/proc", "/sys", "/dev",
    ];
    if DENYLIST
        .iter()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .any(|d| dir == d)
    {
        return true;
    }

    // Any ancestor of $HOME (inclusive) publishes every user's home; an
    // unresolvable $HOME (hardened containers) fails CLOSED.
    let home_overlapped = match directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()) {
        Some(home) => {
            let home = std::fs::canonicalize(&home).unwrap_or(home);
            home.starts_with(&dir)
        }
        None => true,
    };

    // Three-way overlap on purpose: the root itself, a subtree (GETs would
    // serve the token files), and ancestors (would serve registry.json). A
    // not-yet-existing root compares lexically; an undeterminable root
    // fails CLOSED like $HOME.
    let state_overlapped = match crate::state::StateDir::new() {
        Ok(state) => {
            let root =
                std::fs::canonicalize(state.root()).unwrap_or_else(|_| state.root().to_path_buf());
            dir == root || dir.starts_with(&root) || root.starts_with(&dir)
        }
        Err(_) => true,
    };

    home_overlapped || state_overlapped
}

pub(crate) fn resolve_dir(dir: &Path) -> Result<PathBuf> {
    let abs = std::path::absolute(dir)
        .with_context(|| format!("resolving directory {}", dir.display()))?;

    if !abs.exists() {
        bail!("directory '{}' does not exist", abs.display());
    }
    if !abs.is_dir() {
        bail!("'{}' is not a directory", abs.display());
    }
    if !is_readable(&abs) {
        bail!("directory '{}' is not readable", abs.display());
    }
    Ok(abs)
}

/// True if we can read the directory's entries (a proxy for "readable").
fn is_readable(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok()
}

async fn run_background(
    dir: &Path,
    name: Option<String>,
    port: Option<u16>,
    static_flags: StaticFlags,
) -> Result<()> {
    let state = StateDir::new()?;

    // ft binds this port: allocate when omitted, require free when explicit;
    // `is_port_free(0)` reads 0 as "assign me one", so reject 0 explicitly.
    let port = match port {
        Some(p) => {
            ensure!(
                p != 0,
                "port 0 is reserved; pass an explicit port (1-65535) or omit --port"
            );
            ensure!(port::is_port_free(p), "port {p} is already in use");
            p
        }
        None => port::allocate_free_port()?,
    };

    // Looked up before reserving anything, so a missing binary fails without
    // leaving a half-started entry to clean up.
    cloudflared::ensure_installed()?;

    state.ensure()?;

    let (id, name) = reserve_entry(
        &state,
        ServiceKind::Static,
        Some(dir),
        name::generate_name(dir),
        port,
        name,
        0,
        false,
        static_flags,
    )?;

    let worker_pid = match spawn::spawn_worker(id, &name, Some(dir), port) {
        Ok(pid) => pid,
        Err(e) => {
            remove_reservation(&state, id);
            return Err(e);
        }
    };
    record_worker_pid(&state, id, worker_pid)?;

    poll_for_url(&state, id, &name, worker_pid).await
}

/// Reserve a name, id, and entry atomically under the registry lock — the
/// shared reservation of every start flow. `worker_pid: 0` + a fresh
/// `created_at` put the entry inside `model::START_GRACE`, so a concurrent
/// `ft kill`/`ft prune` refuses to reap it during the reserve→spawn→record
/// window; callers resolve the window by removing the entry by id, which
/// bypasses the grace guard (pid-0 staleness is
/// `Service::start_in_progress`'s to own).
#[allow(clippy::too_many_arguments)]
pub(crate) fn reserve_entry(
    state: &StateDir,
    kind: ServiceKind,
    dir: Option<&Path>,
    base: String,
    port: u16,
    name: Option<String>,
    worker_pid: u32,
    foreground: bool,
    static_flags: StaticFlags,
) -> Result<(u64, String)> {
    Registry::update(state, |reg| -> Result<(u64, String)> {
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            None => name::unique_name(reg, &base),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind,
            dir: dir.map(|d| d.to_path_buf()),
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid,
            tunnel_pid: None,
            command_pid: None,
            static_flags,
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground,
        });
        Ok((id, name))
    })?
}

/// Release a reserved entry after the worker spawn failed (best-effort).
pub(crate) fn remove_reservation(state: &StateDir, id: u64) {
    if let Err(cleanup_err) = Registry::update(state, |reg| {
        reg.remove(id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after spawn failure");
    }
}

/// Record the real worker pid under the lock, keyed by id — a name may be
/// reused after a kill; an id is immune and matches the worker's lookup.
pub(crate) fn record_worker_pid(state: &StateDir, id: u64, worker_pid: u32) -> Result<()> {
    Registry::update(state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string()) {
            svc.worker_pid = worker_pid;
        }
    })
}

/// Poll the registry for the worker's published public URL, failing fast if
/// the worker dies or the entry vanishes — the shared tail of the
/// START/PROXY/HOOK background flows (RUN's loop additionally requires the
/// origin port). Re-read+parse only on mtime change; the death probe still
/// runs every poll, so fail-fast latency is unchanged.
pub(crate) async fn poll_for_url(
    state: &StateDir,
    id: u64,
    name: &str,
    worker_pid: u32,
) -> Result<()> {
    let registry_path = state.registry_path();
    let mut last_mtime = std::fs::metadata(&registry_path)
        .and_then(|m| m.modified())
        .ok();
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            break;
        }

        // Cheap stat first; re-read only when the file changed.
        // `None` = did NOT re-read; `Some(None)` = re-read, entry gone.
        let new_mtime = std::fs::metadata(&registry_path)
            .and_then(|m| m.modified())
            .ok();
        let snapshot: Option<Option<Service>> = if new_mtime != last_mtime {
            last_mtime = new_mtime;
            Some(Registry::load(state)?.find(&id.to_string()).cloned())
        } else {
            // Registry unchanged: the worker may still have died silently
            // between rewrites, so probe the recorded pid directly.
            if !proc::pid_alive(worker_pid) {
                return fail_start(state, id, name, worker_pid).await;
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                output::print_started(&svc);
                return Ok(());
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — surface the reason inline
                // (the entry is removed; `ft logs` won't exist afterwards).
                return fail_start(state, id, name, worker_pid).await;
            }
            Some(None) => {
                // Our entry vanished — concurrent `ft kill` or the worker's
                // own self-remove; tear down now, not after 30 s of orphan.
                return fail_start(state, id, name, worker_pid).await;
            }
            // Still starting, or unchanged registry: poll again.
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out: the worker + cloudflared may still be alive, so tear them
    // down before bailing.
    fail_timeout(state, id, name, worker_pid).await
}

/// Group-kill the worker, remove the entry by id (bypasses the start-grace
/// guard — removing our own reservation is always allowed).
pub(crate) async fn teardown(state: &StateDir, id: u64, worker_pid: u32, what: &str) {
    proc::shutdown_process_group(worker_pid).await;
    if let Err(cleanup_err) = Registry::update(state, |reg| {
        reg.remove(id);
    }) {
        tracing::warn!(%cleanup_err, id, "failed to clean up registry entry after {what}");
    }
}

/// Tear the just-started service down and fail — the shared fail-fast arm of
/// the poll loops (worker death, vanished entry).
pub(crate) async fn fail_start(
    state: &StateDir,
    id: u64,
    name: &str,
    worker_pid: u32,
) -> Result<()> {
    teardown(state, id, worker_pid, "worker death").await;
    let reason = last_reason(state, name);
    bail!("worker for '{name}' exited before the tunnel came up{reason}")
}

/// Timed out waiting for the URL: tear the live worker down, remove the
/// entry, and bail.
pub(crate) async fn fail_timeout(
    state: &StateDir,
    id: u64,
    name: &str,
    worker_pid: u32,
) -> Result<()> {
    teardown(state, id, worker_pid, "URL timeout").await;
    let reason = last_reason(state, name);
    bail!("timed out waiting for the tunnel URL{reason}")
}

/// Best-effort last non-empty log line for a start-failure message:
/// `tunnel.log` first (cloudflared errors), then `worker.log`.
pub(crate) fn last_reason(state: &StateDir, name: &str) -> String {
    let pick = [state.tunnel_log(name), state.worker_log(name)]
        .into_iter()
        .find_map(|p| last_line(&p));
    match pick {
        Some(line) => format!(":\n  {line}"),
        None => String::new(),
    }
}

/// The last non-empty line of `path`, reading at most `LAST_REASON_CAP`
/// trailing bytes so a chatty log cannot slurp megabytes into memory.
pub(crate) fn last_line(path: &Path) -> Option<String> {
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
        // Skip the partial first line after a mid-file seek; a window with
        // no newline is one long line — use it rather than drop the reason.
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

/// RAII guard removing a reserved entry on drop — every exit path (early `?`,
/// spawn failure, panic, return). Shared with the hook foreground flow.
pub(crate) struct EntryGuard {
    state: StateDir,
    id: u64,
}

impl EntryGuard {
    pub(crate) fn new(state: StateDir, id: u64) -> Self {
        Self { state, id }
    }
}

impl Drop for EntryGuard {
    fn drop(&mut self) {
        // tracing is sync-safe inside Drop; a failed cleanup must be visible
        // or the entry leaks silently until a later `ft prune`.
        if let Err(e) = Registry::update(&self.state, |reg| {
            reg.remove(self.id);
        }) {
            tracing::warn!(%e, id = self.id, "failed to clean up foreground registry entry on drop");
        }
    }
}

/// Foreground flow: run origin + tunnel in-process until cloudflared exits,
/// Ctrl-C, or (Unix) SIGTERM — what `ft kill` uses from another terminal.
pub(crate) async fn run_foreground(
    dir: Option<&Path>,
    name: Option<String>,
    port: Option<u16>,
) -> Result<()> {
    run_foreground_inner(dir, name, port, None, StaticFlags::default()).await
}

/// `ft <dir> --foreground` with static-origin flags applied to the server
/// and persisted on the reserved entry.
pub(crate) async fn run_foreground_with_options(
    dir: &Path,
    name: Option<String>,
    port: Option<u16>,
    static_flags: StaticFlags,
) -> Result<()> {
    run_foreground_inner(Some(dir), name, port, None, static_flags).await
}

/// `ft run --port <p> -- <cmd> --foreground`: `ft` spawns `command` (PORT
/// exported) as the origin and owns it — it dies with the tunnel, any exit.
pub(crate) async fn run_foreground_with_command(
    name: Option<String>,
    port: Option<u16>,
    command: &[OsString],
) -> Result<()> {
    run_foreground_inner(None, name, port, Some(command), StaticFlags::default()).await
}

/// The shared foreground machinery behind all three entries: `Some(dir)` =
/// static server; `None` + `command` = the operator's command as ft's child;
/// `None` alone = proxy. The entry records our own pid and `foreground:
/// true`, so `ft kill` signals this single pid, never the group (which
/// includes the operator's shell); removed on every exit, stale only on a
/// hard kill (then `ft prune`'s).
async fn run_foreground_inner(
    dir: Option<&Path>,
    name: Option<String>,
    port: Option<u16>,
    command: Option<&[OsString]>,
    static_flags: StaticFlags,
) -> Result<()> {
    use crate::server::static_server;
    use tokio::sync::Mutex;

    let state = StateDir::new()?;
    state.ensure()?;

    // The kind follows the origin, mirroring the registry invariant: a
    // directory means Static, a command means Run, neither means Proxy.
    let kind = if dir.is_some() {
        ServiceKind::Static
    } else if command.is_some() {
        ServiceKind::Run
    } else {
        ServiceKind::Proxy
    };

    // Static: ft binds the port (allocate when omitted, require free when
    // explicit). Proxy/Run: the port is the origin's — required, never probed.
    let port = match dir {
        Some(_) => match port {
            Some(p) => {
                ensure!(
                    p != 0,
                    "port 0 is reserved; pass an explicit port (1-65535) or omit --port"
                );
                ensure!(port::is_port_free(p), "port {p} is already in use");
                p
            }
            None => port::allocate_free_port()?,
        },
        None => match port {
            Some(p) => {
                ensure!(
                    p != 0,
                    "port 0 is reserved; pass an explicit port (1-65535)"
                );
                p
            }
            None => bail!("a proxy or run service needs an explicit port to front"),
        },
    };

    cloudflared::ensure_installed()?;

    // --- Reserve a registry entry ------------------------------------------
    // FOREGROUND entry, worker_pid = THIS process (Windows: the only mode).
    let base = match (dir, command) {
        (Some(d), _) => name::generate_name(d),
        (None, Some(_)) => format!("run-{port}"),
        (None, None) => format!("proxy-{port}"),
    };
    let (id, name) = reserve_entry(
        &state,
        kind,
        dir,
        base,
        port,
        name,
        std::process::id(),
        true,
        static_flags.clone(),
    )?;

    // From here, every exit path releases the entry via the guard's Drop.
    let _entry = EntryGuard::new(state.clone(), id);

    // Tee cloudflared output to tunnel.log so `ft logs <name>` works for
    // foreground tunnels (which otherwise only print to the terminal).
    let tunnel_log = state.tunnel_log(&name);
    let log_writer = Arc::new(Mutex::new(
        crate::fsutil::open_private_append_async(&tunnel_log)
            .await
            .with_context(|| format!("opening tunnel log {}", tunnel_log.display()))?,
    ));

    // Install the SIGTERM handler BEFORE spawning server + cloudflared: on
    // failure the `?` leaves only the guard-protected entry, no orphans.
    #[cfg(unix)]
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    // Static only: ft's own server. A proxy foreground runs no server — the
    // handle stays `None` and the drain below is skipped.
    let mut server_handle = dir.map(|dir| {
        // The flags configure the same router the detached worker would build.
        let router = static_server::router_with(dir.to_path_buf(), static_flags.clone());
        // `serve` installs its own Ctrl-C handler and drains in-flight
        // requests; the handle bounds that drain below.
        tokio::spawn(async move {
            if let Err(e) = static_server::serve(router, port).await {
                tracing::error!(%e, "static server exited with error");
            }
        })
    });

    // Run only: open the command's log sink BEFORE spawning the child, so a
    // failure to open worker.log can never orphan an already-running command.
    let command_writer = match command {
        Some(_) => {
            let command_log = state.worker_log(&name);
            Some(Arc::new(Mutex::new(
                crate::fsutil::open_private_append_async(&command_log)
                    .await
                    .with_context(|| format!("opening worker log {}", command_log.display()))?,
            )))
        }
        None => None,
    };

    // Run only: spawn the operator's command as THIS process's child — the
    // origin cloudflared fronts, PORT exported; no static server to unwind.
    let (command_pid, mut command_monitor, command_out) = match command {
        Some(cmd) => {
            let mut child = crate::proc::spawn_command_child(cmd, port)?;
            // A freshly spawned, unreaped child always reports its pid (see
            // the matching note in worker.rs).
            let pid = child.id();
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let monitor = crate::proc::spawn_wait_monitor(child);
            (pid, monitor, (stdout, stderr))
        }
        None => (
            None,
            crate::proc::command_monitor_placeholder(),
            (None, None),
        ),
    };
    // Record the command pid the moment it exists (Run only). Warn, not `?`:
    // the shutdown path below tears the child down on every exit anyway.
    if let Some(pid) = command_pid
        && let Err(e) = Registry::update(&state, |reg| {
            if let Some(svc) = reg.find_mut(&id.to_string()) {
                svc.command_pid = Some(pid);
            }
        })
    {
        tracing::warn!(%e, id, "failed to record the command pid on the registry entry");
    }

    // Tee the command's output to the terminal AND worker.log (mirroring
    // cloudflared's tee below) so `ft logs` works after the session ends.
    let (command_stdout, command_stderr) = command_out;
    let mut command_tasks = Vec::new();
    if let Some(command_writer) = command_writer {
        if let Some(out) = command_stdout {
            command_tasks.push(tokio::spawn(drain_to_log(
                BufReader::new(out),
                command_writer.clone(),
            )));
        }
        if let Some(err) = command_stderr {
            command_tasks.push(tokio::spawn(drain_to_log(
                BufReader::new(err),
                command_writer,
            )));
        }
    }

    let mut child = match cloudflared::spawn(port) {
        Ok(c) => c,
        Err(e) => {
            // Abort the just-spawned server task; the entry goes via the
            // guard. The command child must not outlive a dead tunnel.
            if let Some(server) = server_handle.as_mut() {
                server.abort();
            }
            crate::proc::shutdown_child_command(command_pid, &mut command_monitor).await;
            return Err(e);
        }
    };
    let tunnel_pid = child.id();

    // Mirror cloudflared's combined output to stdout AND tunnel.log, and publish
    // the public URL on first discovery (so `ft open`/`ft detail` work too).
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

    // Race both children plus Ctrl-C/SIGTERM: a dead cloudflared OR a dead
    // dev server tears the tunnel down instead of hanging or 502-ing.
    #[cfg(unix)]
    let exit_reason = tokio::select! {
        status = child.wait() => {
            match status {
                Ok(s) => tracing::info!(?s, "cloudflared exited"),
                Err(e) => tracing::error!(%e, "waiting on cloudflared failed"),
            }
            ReaderExit::ChildExited
        }
        _ = &mut command_monitor => {
            tracing::info!("command child exited, shutting down foreground tunnel");
            ReaderExit::CommandExited
        }
        _ = sig_term.recv() => {
            tracing::info!("received SIGTERM, shutting down foreground tunnel");
            ReaderExit::Signal
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl-C, shutting down foreground tunnel");
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
        _ = &mut command_monitor => {
            tracing::info!("command child exited, shutting down foreground tunnel");
            ReaderExit::CommandExited
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl-C, shutting down foreground tunnel");
            ReaderExit::Signal
        }
    };

    // If cloudflared may still be alive, shut it down and reap it (on
    // ChildExited the select's wait() already reaped it).
    if matches!(exit_reason, ReaderExit::Signal) {
        cloudflared::shutdown(tunnel_pid, &mut child).await;
    }

    // The command child must never outlive the tunnel on ANY exit (the
    // shutdown skips itself when the monitor saw the exit); no-op for non-run.
    crate::proc::shutdown_child_command(command_pid, &mut command_monitor).await;

    for task in command_tasks {
        task.abort();
    }

    for task in tasks {
        task.abort();
    }

    // Bound serve's Ctrl-C drain so a stuck request can't hang the command,
    // falling back to abort; a proxy foreground has no server to drain.
    if let Some(server) = server_handle.as_mut() {
        // Reborrow so the handle stays usable in the abort fallback below.
        match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut *server).await {
            Ok(_) => {}
            Err(_) => {
                tracing::warn!(
                    "static server did not drain within {:?}, aborting",
                    SERVER_SHUTDOWN_TIMEOUT
                );
                server.abort();
            }
        }
    }

    // The command itself died: a foreground tunnel whose origin is gone
    // serves only 502s — fail. (Signal/child-exit flows return Ok.)
    if matches!(exit_reason, ReaderExit::CommandExited) {
        let bin = command
            .and_then(|c| c.first())
            .map(|b| b.to_string_lossy().into_owned())
            .unwrap_or_default();
        bail!("command '{bin}' exited — tunnel torn down");
    }

    Ok(())
}

/// Why the foreground keep-alive loop ended — drives cloudflared teardown.
enum ReaderExit {
    ChildExited,
    /// The run flow's command child exited — the origin is gone.
    CommandExited,
    Signal,
}

/// Read `lines` to EOF, printing to stdout AND appending to the log — the
/// command-child counterpart of [`drain_and_announce`], minus URL extraction.
async fn drain_to_log<R>(reader: BufReader<R>, log_writer: Arc<tokio::sync::Mutex<tokio::fs::File>>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        println!("{line}");
        {
            let mut f = log_writer.lock().await;
            let _ = f.write_all(line.as_bytes()).await;
            let _ = f.write_all(b"\n").await;
            let _ = f.flush().await;
        }
    }
}

/// Mirror `lines` to stdout AND `tunnel.log`, publishing the first discovered
/// Quick Tunnel URL onto the registry entry. Shared with the hook flow.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drain_and_announce<R>(
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

#[cfg(test)]
mod tests {
    use super::{EntryGuard, is_sensitive_dir};
    use crate::model::{Registry, Service, ServiceKind, StaticFlags};
    use crate::state::StateDir;
    #[cfg(unix)]
    use std::path::Path;
    use std::path::PathBuf;

    #[test]
    fn sensitive_home_and_its_ancestor() {
        let home = directories::BaseDirs::new()
            .expect("home dir")
            .home_dir()
            .to_path_buf();
        assert!(is_sensitive_dir(&home), "$HOME itself must be sensitive");
        // An ancestor of $HOME publishes every user's home — sensitive too.
        if let Some(parent) = home.parent() {
            assert!(
                is_sensitive_dir(parent),
                "{parent:?} should be sensitive (ancestor of $HOME)"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_system_dirs() {
        // Existence-guarded so this passes in minimal containers too.
        for d in ["/etc", "/var", "/dev", "/proc", "/sys"] {
            if Path::new(d).exists() {
                assert!(is_sensitive_dir(Path::new(d)), "{d} should be sensitive");
            }
        }
    }

    #[test]
    fn normal_dir_not_sensitive() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!is_sensitive_dir(dir.path()));
    }

    /// Build a `StateDir` rooted at a temp dir, ready for registry operations.
    fn fresh_state() -> (tempfile::TempDir, StateDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new_at(tmp.path().join("ft-state"));
        state.ensure().expect("ensure state dir");
        Registry::default()
            .save(&state)
            .expect("seed empty registry");
        (tmp, state)
    }

    fn seed_entry(state: &StateDir, id: u64) {
        Registry::update(state, |reg| {
            reg.services.push(Service {
                id,
                name: format!("svc-{id}"),
                kind: ServiceKind::Static,
                dir: Some(PathBuf::from("/tmp")),
                port: 8000,
                local_url: "http://127.0.0.1:8000".to_string(),
                public_url: None,
                worker_pid: 0,
                tunnel_pid: None,
                command_pid: None,
                static_flags: StaticFlags::default(),
                created_at: crate::model::now_utc(),
                state_dir: PathBuf::from("/tmp"),
                foreground: true,
            });
        })
        .expect("seed entry");
    }

    fn entry_present(state: &StateDir, id: u64) -> bool {
        Registry::load(state)
            .map(|reg| reg.find(&id.to_string()).is_some())
            .unwrap_or(false)
    }

    #[test]
    fn entry_guard_removes_entry_on_drop() {
        let (_tmp, state) = fresh_state();
        let id = 42;
        seed_entry(&state, id);
        assert!(entry_present(&state, id), "entry should exist before drop");

        {
            let _entry = EntryGuard::new(state.clone(), id);
        }

        assert!(
            !entry_present(&state, id),
            "EntryGuard must remove the registry entry on drop"
        );
    }

    #[test]
    fn entry_guard_removes_entry_on_panic() {
        // Drop must fire even when the owning scope unwinds; catch_unwind
        // triggers it without aborting the process (fields are UnwindSafe).
        let (_tmp, state) = fresh_state();
        let id = 7;
        seed_entry(&state, id);

        let guard_state = state.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _entry = EntryGuard::new(guard_state, id);
            panic!("simulated failure between reserve and explicit removal");
        }));
        assert!(result.is_err(), "the closure should have panicked");

        assert!(
            !entry_present(&state, id),
            "EntryGuard must remove the registry entry even on panic"
        );
    }
}
