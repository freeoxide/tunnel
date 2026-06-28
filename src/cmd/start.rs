//! The START command.
//!
//! `ft <dir>` (no subcommand) starts a tunnel for a local directory. The
//! default background flow reserves a registry entry, spawns a detached worker
//! that owns the static server and the `cloudflared` child, then polls the
//! registry for the discovered public URL — failing fast if the worker dies
//! before publishing. With `--foreground` the server and tunnel run in-process
//! and the command blocks until Ctrl+C.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

/// Reload cadence while waiting for the worker to publish the public URL.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Upper bound on how long the parent will wait for the tunnel URL.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Entry point for the START command.
///
/// `dir` defaults to `.` when the caller passes `None`.
pub async fn run(
    dir: Option<PathBuf>,
    name: Option<String>,
    port: Option<u16>,
    foreground: bool,
) -> Result<()> {
    let dir = dir.unwrap_or_else(|| PathBuf::from("."));
    let dir = resolve_dir(&dir)?;

    if foreground {
        run_foreground(&dir, name, port).await
    } else {
        run_background(&dir, name, port).await
    }
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
async fn run_background(dir: &Path, name: Option<String>, port: Option<u16>) -> Result<()> {
    let state = StateDir::new()?;

    // --- Port -------------------------------------------------------------
    let port = match port {
        Some(p) => {
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
        std::fs::create_dir_all(state.service_dir(&name))
            .with_context(|| format!("creating service directory for '{name}'"))?;
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
            created_at: chrono::Utc::now(),
            state_dir: state.service_dir(&name),
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
    // Record the real worker pid under the lock so we never clobber the
    // worker's own public_url write.
    Registry::update(&state, |reg| {
        if let Some(svc) = reg.find_mut(&name) {
            svc.worker_pid = worker_pid;
        }
    })?;

    // --- Poll for the tunnel URL (fail-fast on worker death) --------------
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let snapshot = Registry::load(&state)?.find(&name).cloned();
        match snapshot {
            Some(svc) if svc.public_url.is_some() => {
                output::print_started(&svc);
                return Ok(());
            }
            Some(svc) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — clean up and fail fast.
                proc::shutdown_process_group(worker_pid);
                let _ = Registry::update(&state, |reg| {
                    reg.remove(id);
                });
                bail!(
                    "worker for '{name}' exited before the tunnel came up — see `ft logs {name}`"
                );
            }
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    bail!("timed out waiting for the tunnel URL — check `ft logs {name}`")
}

/// Foreground flow: run the server and tunnel in this process and block until
/// interrupted. No registry entry is written.
async fn run_foreground(dir: &Path, name: Option<String>, port: Option<u16>) -> Result<()> {
    use crate::static_server;
    use std::time::Duration;

    /// Upper bound on draining in-flight requests on Ctrl-C before we abort the
    /// server task, so a stuck request can't hang the foreground command.
    const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

    let display_name = name.unwrap_or_else(|| name::generate_name(dir));

    let port = match port {
        Some(p) => {
            ensure!(port::is_port_free(p), "port {p} is already in use");
            p
        }
        None => port::allocate_free_port()?,
    };

    cloudflared::ensure_installed()?;

    let router = static_server::router(dir.to_path_buf());
    // `serve` installs its own Ctrl-C handler for graceful shutdown: on Ctrl-C
    // it stops accepting and drains in-flight requests. We keep the JoinHandle
    // so we can bound that drain below.
    let mut server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "static server exited with error");
        }
    });

    let mut child = cloudflared::spawn(port, PathBuf::new())?;
    let tunnel_pid = child.id();

    // Mirror cloudflared's combined output to stdout and print the success
    // banner on first URL discovery.
    let found = Arc::new(AtomicBool::new(false));

    let mut tasks = Vec::new();
    if let Some(out) = child.stdout.take() {
        let found = found.clone();
        let display_name = display_name.clone();
        tasks.push(tokio::spawn(async move {
            drain_and_announce(BufReader::new(out).lines(), found, &display_name, port).await;
        }));
    }
    if let Some(err) = child.stderr.take() {
        let found = found.clone();
        let display_name = display_name.clone();
        tasks.push(tokio::spawn(async move {
            drain_and_announce(BufReader::new(err).lines(), found, &display_name, port).await;
        }));
    }

    tokio::signal::ctrl_c()
        .await
        .context("installing Ctrl-C handler")?;

    tracing::info!("received Ctrl-C, shutting down foreground tunnel");

    if let Some(pid) = tunnel_pid {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
    }

    for task in tasks {
        task.abort();
    }

    // `serve`'s own Ctrl-C handler has already begun draining; bound it so a
    // stuck request can't hang the foreground command, falling back to abort.
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

    Ok(())
}

/// Read `lines` to EOF, mirroring each to stdout, and print the foreground
/// success banner on the first discovered Quick Tunnel URL.
async fn drain_and_announce<R>(
    mut lines: tokio::io::Lines<R>,
    found: Arc<AtomicBool>,
    display_name: &str,
    port: u16,
) where
    R: tokio::io::AsyncBufRead + Unpin,
{
    while let Ok(Some(line)) = lines.next_line().await {
        println!("{line}");
        if !found.load(Ordering::Acquire)
            && let Some(url) = cloudflared::extract_url(&line)
        {
            println!();
            println!("Started {display_name}");
            println!();
            println!("Local:   http://127.0.0.1:{port}");
            println!("Public:  {url}");
            println!();
            found.store(true, Ordering::Release);
        }
    }
}
