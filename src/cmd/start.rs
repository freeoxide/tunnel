//! The START command.
//!
//! `ft <dir>` (no subcommand) starts a tunnel for a local directory. The
//! default background flow reserves a registry entry, spawns a detached worker
//! that owns the static server and the `cloudflared` child, then polls the
//! registry for the discovered public URL — failing fast if the worker dies
//! before publishing. With `--foreground` the server and tunnel run in-process
//! and the command blocks until cloudflared exits or Ctrl+C is received.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::cloudflared;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::name;
use crate::output;
use crate::port;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;
use std::time::Instant;

/// Reload cadence while waiting for the worker to publish the public URL.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Upper bound on how long the parent will wait for the tunnel URL.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);
/// Most bytes read from a log when surfacing a start-failure reason. Logs can
/// grow large; only the trailing window is examined (the first, partial line
/// after a mid-file seek is skipped).
const LAST_REASON_CAP: u64 = 16 * 1024;

/// Entry point for the START command.
///
/// `dir` defaults to `.` when the caller passes `None`.
pub async fn run(
    dir: Option<PathBuf>,
    name: Option<String>,
    port: Option<u16>,
    foreground: bool,
    yes: bool,
) -> Result<()> {
    let dir = dir.unwrap_or_else(|| PathBuf::from("."));
    let dir = resolve_dir(&dir)?;
    // Guard the most foot-gun cases: publishing the whole home directory or the
    // filesystem root to the public internet. Dotfiles are already refused by
    // the server (C1), but `$HOME` still exposes most of a user's life.
    confirm_sensitive(&dir, yes)?;

    if foreground {
        run_foreground(&dir, name, port).await
    } else {
        run_background(&dir, name, port).await
    }
}

/// Refuse — or prompt for confirmation — when the served directory is a
/// sensitive one (the home directory or `/`). Non-interactive runs must pass
/// `yes`; a TTY gets a y/N prompt (default No).
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
/// mistake.
///
/// Flags:
/// - the filesystem root and well-known system directories (`/etc`, `/root`,
///   `/var`, `/home`, `/Users`, `/proc`, `/sys`, `/dev`);
/// - any **ancestor** of `$HOME` (e.g. `ft ~..`, `ft /home`, `ft /Users`,
///   `ft C:\Users`) — publishing it would expose every user's home non-dotfile
///   contents;
/// - `$HOME` itself.
///
/// Both sides are canonicalised so a symlink alias of `$HOME` (e.g.
/// `ft ~/house` where `house -> $HOME`) cannot slip past the prompt; if the
/// directory cannot be canonicalised (a symlink loop, permission issue, etc.)
/// we fail CLOSED (treat it as sensitive) rather than compare an un-resolved
/// path. The dotfile confinement (C1) still denies `.env`/`.ssh`/`.git`/etc.
/// regardless; this guard covers the bulk of a sensitive tree that is *not*
/// dotfile-hidden.
fn is_sensitive_dir(dir: &Path) -> bool {
    let Ok(dir) = std::fs::canonicalize(dir) else {
        return true; // fail-closed: can't resolve it -> refuse to publish silently.
    };

    // System roots/directories whose wholesale exposure is a foot-gun. The
    // Unix-specific entries are harmless no-ops on Windows (they never match).
    const DENYLIST: &[&str] = &[
        "/", "/etc", "/root", "/var", "/home", "/Users", "/proc", "/sys", "/dev",
    ];
    if DENYLIST.iter().any(|d| dir == Path::new(d)) {
        return true;
    }

    // Any ancestor of $HOME (inclusive) publishes every user's home contents.
    if let Some(home) = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()) {
        let home = std::fs::canonicalize(&home).unwrap_or(home);
        return home.starts_with(&dir);
    }
    false
}

/// Resolve a directory to an absolute, existing, readable path.
fn resolve_dir(dir: &Path) -> Result<PathBuf> {
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

/// Background flow: reserve the entry, spawn the detached worker, then poll for
/// the public URL (failing fast if the worker dies first).
///
/// Cross-platform: on Unix the worker is detached via `setsid` and torn down by
/// `kill(-pgid)`; on Windows it is detached via `CREATE_NEW_PROCESS_GROUP |
/// DETACHED_PROCESS` and owns a `KILL_ON_JOB_CLOSE` Job Object. Both are hidden
/// behind [`spawn::spawn_worker`] and [`proc::shutdown_process_group`].
async fn run_background(dir: &Path, name: Option<String>, port: Option<u16>) -> Result<()> {
    run_background_impl(dir, name, port).await
}

async fn run_background_impl(dir: &Path, name: Option<String>, port: Option<u16>) -> Result<()> {
    let state = StateDir::new()?;

    // --- Port -------------------------------------------------------------
    // `is_port_free(0)` misleadingly returns true (the kernel treats 0 as
    // "assign me one"), so reject it explicitly.
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

    // --- cloudflared ------------------------------------------------------
    cloudflared::ensure_installed()?;

    state.ensure()?;

    // --- Reserve name + id + entry atomically -----------------------------
    // All under the registry lock: no duplicate names, no duplicate ids, and
    // the entry exists before the worker is spawned. worker_pid is 0 until the
    // worker is spawned below.
    let (id, name) = Registry::update(&state, |reg| -> Result<(u64, String)> {
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            None => name::unique_name(reg, &name::generate_name(dir)),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Static,
            dir: dir.to_path_buf(),
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground: false,
        });
        Ok((id, name))
    })??;

    // --- Spawn worker -----------------------------------------------------
    let worker_pid = match spawn::spawn_worker(id, &name, dir, port) {
        Ok(pid) => pid,
        Err(e) => {
            // Release the reserved entry on spawn failure.
            let _ = Registry::update(&state, |reg| {
                reg.remove(id);
            });
            return Err(e);
        }
    };
    // Record the real worker pid under the lock. Key by the stable numeric id,
    // not the name: the name may be reused for a fresh service after a kill,
    // and an id key is immune to that (and matches how the worker looks itself
    // up), so a concurrent kill cannot make us record the pid against the wrong
    // entry.
    Registry::update(&state, |reg| {
        if let Some(svc) = reg.find_mut(&id.to_string()) {
            svc.worker_pid = worker_pid;
        }
    })?;

    // --- Poll for the tunnel URL (fail-fast on worker death) --------------
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let snapshot = Registry::load(&state)?.find(&id.to_string()).cloned();
        match snapshot {
            Some(svc) if svc.public_url.is_some() => {
                output::print_started(&svc);
                return Ok(());
            }
            Some(svc) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — reap any survivors, surface
                // the reason inline (the entry is removed below, so we can't
                // send the user to `ft logs` afterwards), then fail fast.
                proc::shutdown_process_group(worker_pid).await;
                let reason = last_reason(&state, &name);
                let _ = Registry::update(&state, |reg| {
                    reg.remove(id);
                });
                bail!("worker for '{name}' exited before the tunnel came up{reason}");
            }
            None => {
                // Our entry vanished — a concurrent `ft kill` removed it, or the
                // worker self-removed on its own failure. Tear the worker down
                // and bail now instead of polling the full 30s with a live,
                // orphaned worker that nothing in the registry points at.
                proc::shutdown_process_group(worker_pid).await;
                let reason = last_reason(&state, &name);
                let _ = Registry::update(&state, |reg| {
                    reg.remove(id);
                });
                bail!("worker for '{name}' exited before the tunnel came up{reason}");
            }
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out: the worker + cloudflared may still be alive and the entry is
    // still active, so tear them down like the fail-fast path before bailing.
    proc::shutdown_process_group(worker_pid).await;
    let _ = Registry::update(&state, |reg| {
        reg.remove(id);
    });
    let reason = last_reason(&state, &name);
    bail!("timed out waiting for the tunnel URL{reason}")
}

/// Best-effort last non-empty log line to surface in a start-failure message.
/// Checks `tunnel.log` first (cloudflared's own output, where errors usually
/// appear), then `worker.log`. Returns an empty string if nothing useful is
/// found.
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
/// slurp megabytes into memory.
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

/// RAII guard that removes a reserved registry entry on drop.
///
/// Ensures EVERY exit path out of `run_foreground` — early `?` returns, the
/// cloudflared-spawn-failure arm, a panic, and the normal return — cleans up the
/// registry entry it reserved. Without this, a failure between the reserve and
/// the final explicit removal (e.g. opening tunnel.log, installing the SIGTERM
/// handler) would leak a stale entry.
struct EntryGuard {
    state: StateDir,
    id: u64,
}

impl Drop for EntryGuard {
    fn drop(&mut self) {
        let _ = Registry::update(&self.state, |reg| {
            reg.remove(self.id);
        });
    }
}

/// Foreground flow: run the server and tunnel in this process and block until
/// cloudflared exits, Ctrl-C is received, or (Unix) SIGTERM arrives — SIGTERM
/// is what `ft kill` uses to stop a foreground tunnel from another terminal.
///
/// Unlike the background flow, the server + cloudflared live in THIS process,
/// so the registry entry records `worker_pid` as our own pid and is marked
/// `foreground: true`. That flag makes `status()` use a plain liveness probe
/// (our cmdline lacks the `run-worker` token) and makes `ft kill` signal this
/// single pid rather than its whole process group (which would include the
/// operator's shell). The entry is removed on every exit path; a hard kill
/// (SIGKILL/crash) leaves it stale for `ft prune` to reap.
async fn run_foreground(dir: &Path, name: Option<String>, port: Option<u16>) -> Result<()> {
    use crate::static_server;
    use std::time::Duration;
    use tokio::sync::Mutex;

    /// Grace window after SIGTERM before SIGKILL'ing cloudflared (Unix only).
    #[cfg(unix)]
    const CLOUDFLARED_GRACE: Duration = Duration::from_secs(2);
    /// Upper bound on draining in-flight requests on Ctrl-C before we abort the
    /// server task, so a stuck request can't hang the foreground command.
    const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

    let state = StateDir::new()?;
    state.ensure()?;

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

    cloudflared::ensure_installed()?;

    // --- Reserve a registry entry (cross-platform) -------------------------
    // Mirrors `run_background_impl`'s reservation, but marks this as a FOREGROUND
    // service whose worker_pid is THIS process. That makes `ft ls/detail/logs/
    // open` see the foreground tunnel on every platform — notably Windows, where
    // foreground is the only mode.
    let (id, name) = Registry::update(&state, |reg| -> Result<(u64, String)> {
        let name = match &name {
            Some(n) => {
                name::validate_name(n)?;
                ensure!(!reg.name_exists(n), "a service named '{n}' already exists");
                n.clone()
            }
            None => name::unique_name(reg, &name::generate_name(dir)),
        };
        let service_dir = state.ensure_service_dir(&name)?;
        let id = reg.allocate_id();
        reg.services.push(Service {
            id,
            name: name.clone(),
            kind: ServiceKind::Static,
            dir: dir.to_path_buf(),
            port,
            local_url: format!("http://127.0.0.1:{port}"),
            public_url: None,
            worker_pid: std::process::id(),
            tunnel_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: service_dir,
            foreground: true,
        });
        Ok((id, name))
    })??;

    // From here, every exit path must release the reserved entry. The guard's
    // Drop removes it on early `?` returns, the spawn-failure arm, a panic, and
    // the normal return alike — so a failure between reserve and the end of the
    // function (opening tunnel.log, installing the SIGTERM handler, etc.) can no
    // longer leak a stale entry.
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

    // Install the SIGTERM handler (Unix) BEFORE spawning the server + cloudflared:
    // if it fails the `?` returns with only the (guard-protected) entry to clean
    // up — no orphaned server task or cloudflared child is left behind.
    #[cfg(unix)]
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    let router = static_server::router(dir.to_path_buf());
    // `serve` installs its own Ctrl-C handler for graceful shutdown: on Ctrl-C
    // it stops accepting and drains in-flight requests. We keep the JoinHandle
    // so we can bound that drain below.
    let mut server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "static server exited with error");
        }
    });

    let mut child = match cloudflared::spawn(port, PathBuf::new()) {
        Ok(c) => c,
        Err(e) => {
            // Abort the just-spawned server task; the entry is released by the
            // guard on return.
            server_handle.abort();
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

    // Keep the foreground alive until cloudflared exits, Ctrl-C is received, or
    // (Unix) SIGTERM arrives. Racing child.wait() ensures that if cloudflared
    // dies before the URL is found (or any time later) we tear down instead of
    // hanging forever.
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
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl-C, shutting down foreground tunnel");
            ReaderExit::Signal
        }
    };

    // If cloudflared may still be alive, shut it down and reap it to avoid a
    // transient zombie. On ChildExited the select's wait() already reaped it.
    if matches!(exit_reason, ReaderExit::Signal) {
        #[cfg(unix)]
        {
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
        }
        #[cfg(not(unix))]
        {
            // No graceful signal path on Windows; force-kill the owned child.
            let _ = tunnel_pid;
            let _ = child.start_kill();
        }
        let _ = child.wait().await; // ensure reaped
    }

    for task in tasks {
        task.abort();
    }

    // `serve`'s own Ctrl-C handler has already begun draining on Ctrl-C; bound
    // it so a stuck request can't hang the foreground command, falling back to
    // abort. (On cloudflared-initiated exit, serve is still running until we
    // abort/await it here.)
    match tokio::time::timeout(SERVER_SHUTDOWN_TIMEOUT, &mut server_handle).await {
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(
                "static server did not drain within {:?}, aborting",
                SERVER_SHUTDOWN_TIMEOUT
            );
            server_handle.abort();
        }
    }

    // The `_entry` guard removes our registry entry on return (every exit path).
    Ok(())
}

/// Why the foreground keep-alive loop ended — drives cloudflared teardown.
enum ReaderExit {
    ChildExited,
    Signal,
}

/// Read `lines` to EOF, mirror each line to stdout AND `tunnel.log`, and publish
/// the first discovered Quick Tunnel URL onto the registry entry (printing the
/// foreground success banner at the same time).
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

#[cfg(test)]
mod tests {
    use super::is_sensitive_dir;
    use std::path::Path;

    #[test]
    fn sensitive_home_and_its_ancestor() {
        let home = directories::BaseDirs::new()
            .expect("home dir")
            .home_dir()
            .to_path_buf();
        assert!(is_sensitive_dir(&home), "$HOME itself must be sensitive");
        // Any ancestor of $HOME (its parent) publishes every user's home, so it
        // must be sensitive too (the CLI-1 fix — previously only exact $HOME).
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
}
