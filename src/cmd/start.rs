//! The START command.
//!
//! `ft <dir>` (no subcommand) starts a tunnel for a local directory. The
//! default background flow spawns a detached worker that owns the static
//! server and the `cloudflared` child; the parent then polls the registry for
//! the discovered public URL and returns. With `--foreground` the server and
//! tunnel run in-process and the command blocks until Ctrl+C.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::cloudflared;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::name;
use crate::output;
use crate::port;
use crate::spawn;
use crate::state::StateDir;

/// Reload cadence while waiting for the worker to publish the public URL.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Upper bound on how long the parent will wait for the tunnel URL.
const POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Entry point for the START command.
///
/// `dir` defaults to `.` when the caller passes `None`. When `foreground` is
/// true the server and tunnel run in this process (no registry entry); otherwise
/// a detached worker is spawned and the parent waits for the URL.
pub async fn run(dir: Option<PathBuf>, name: Option<String>, port: Option<u16>, foreground: bool) -> Result<()> {
    let dir = dir.unwrap_or_else(|| PathBuf::from("."));
    let dir = resolve_dir(&dir)?;

    if foreground {
        run_foreground(&dir, name, port).await
    } else {
        run_background(&dir, name, port).await
    }
}

/// Resolve a directory to an absolute, existing, readable path.
///
/// Friendly errors for the common failure modes (missing / not a directory /
/// unreadable) keep the CLI output clean.
fn resolve_dir(dir: &Path) -> Result<PathBuf> {
    let abs = std::path::absolute(dir)
        .with_context(|| format!("resolving directory {}", dir.display()))?;

    if !abs.exists() || !abs.is_dir() {
        bail!("directory '{}' does not exist", abs.display());
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

/// Background flow: validate inputs, write the registry entry, spawn the
/// detached worker, then poll for the public URL.
async fn run_background(dir: &Path, name: Option<String>, port: Option<u16>) -> Result<()> {
    let state = StateDir::new()?;

    // --- Name -------------------------------------------------------------
    // Validate an explicit name (and reject duplicates), or generate a unique
    // one derived from the directory basename.
    let mut registry = Registry::load(&state)?;
    let name = match name {
        Some(n) => {
            name::validate_name(&n)?;
            ensure!(
                !registry.name_exists(&n),
                "a service named '{n}' already exists"
            );
            n
        }
        None => {
            let base = name::generate_name(dir);
            name::unique_name(&registry, &base)
        }
    };

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

    // --- State + registry entry -------------------------------------------
    state.ensure()?;
    std::fs::create_dir_all(state.service_dir(&name))
        .with_context(|| format!("creating service directory for '{name}'"))?;

    // Reload so the id is allocated against the freshest registry; the worker
    // recovers this same entry by name.
    registry = Registry::load(&state)?;
    let id = registry.allocate_id();
    let service = Service {
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
    };
    registry.services.push(service);
    registry.save(&state)?;

    // --- Spawn worker -----------------------------------------------------
    let worker_pid = spawn::spawn_worker(id, &name, dir, port)?;
    // Record the worker pid so liveness checks work immediately.
    {
        let mut registry = Registry::load(&state)?;
        if let Some(svc) = registry.find_mut(&name) {
            svc.worker_pid = worker_pid;
        }
        registry.save(&state)?;
    }

    // --- Poll for the tunnel URL -----------------------------------------
    let mut final_service = None;
    let deadline = Instant::now() + POLL_TIMEOUT;
    while Instant::now() < deadline {
        let registry = Registry::load(&state)?;
        if let Some(svc) = registry.find(&name) {
            if svc.public_url.is_some() {
                final_service = Some(svc.clone());
                break;
            }
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    match final_service {
        Some(svc) => {
            output::print_started(&svc);
            Ok(())
        }
        None => {
            bail!("timed out waiting for the tunnel URL — check 'ft logs {name}'")
        }
    }
}

/// Foreground flow: run the server and tunnel in this process and block until
/// interrupted. No registry entry is written.
async fn run_foreground(dir: &Path, name: Option<String>, port: Option<u16>) -> Result<()> {
    use crate::static_server;

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
    let server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "static server exited with error");
        }
    });

    let mut child = cloudflared::spawn(port, PathBuf::new())?;
    let tunnel_pid = child.id();

    // Mirror cloudflared's combined output to stdout and print the success
    // banner on first URL discovery. First discovery wins. `ChildStdout` and
    // `ChildStderr` are distinct types, so each stream gets its own reader task
    // sharing the same discovery flag.
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

    // Wait for Ctrl+C, then signal cloudflared and clean up.
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
    server_handle.abort();

    Ok(())
}

/// Read `lines` to EOF, mirroring each to stdout, and print the foreground
/// success banner on the first discovered Quick Tunnel URL.
///
/// Shared across cloudflared's stdout and stderr reader tasks via `found`
/// (first discovery wins) and the borrow-checked `&display_name`/`port` (both
/// `Copy`/cheap, so the borrow is sufficient).
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
        if !found.load(Ordering::Acquire) {
            if let Some(url) = cloudflared::extract_url(&line) {
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
}
