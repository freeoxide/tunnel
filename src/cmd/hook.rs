//! The HOOK command: an ft-owned webhook receiver/inspector origin (see
//! `hook_server`) behind a Quick Tunnel; the port is ft's own and must be
//! free. Keep the foreground teardown order in sync with start's.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

use super::start;
use crate::cloudflared;
use crate::error::Result;
use crate::model::ServiceKind;
use crate::port;
use crate::server::hook_server::{self, HookLog};
use crate::spawn;
use crate::state::StateDir;

pub async fn run(
    port: Option<u16>,
    name: Option<String>,
    foreground: bool,
    keep: Option<u16>,
) -> Result<()> {
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
    let keep = keep.unwrap_or(hook_server::DEFAULT_KEEP);

    if foreground {
        run_foreground(port, name, keep).await
    } else {
        run_background(port, name, keep).await
    }
}

async fn open_hook_log(
    state: &StateDir,
    name: &str,
    keep: u16,
) -> Result<Arc<std::sync::Mutex<HookLog>>> {
    let state = state.clone();
    let name = name.to_string();
    tokio::task::spawn_blocking(move || {
        state.ensure_service_dir(&name)?;
        let path = state
            .service_dir(&name)
            .join(hook_server::REQUESTS_FILENAME);
        let log = HookLog::load(path.clone(), usize::from(keep))
            .with_context(|| format!("opening hook request store {}", path.display()))?;
        Ok(Arc::new(std::sync::Mutex::new(log)))
    })
    .await
    .context("joining the hook request store load task")?
}

async fn run_background(port: u16, name: Option<String>, keep: u16) -> Result<()> {
    let state = StateDir::new()?;

    cloudflared::ensure_installed()?;

    state.ensure()?;

    let (id, name) = start::reserve_entry(
        &state,
        ServiceKind::Hook,
        None,
        format!("hook-{port}"),
        port,
        name,
        0,
        false,
        Default::default(),
    )?;

    let worker_pid = match spawn::spawn_hook_worker(id, &name, port, keep) {
        Ok(pid) => pid,
        Err(e) => {
            start::remove_reservation(&state, id);
            return Err(e);
        }
    };
    start::record_worker_pid(&state, id, worker_pid)?;

    start::poll_for_url(&state, id, &name, worker_pid).await
}

enum ReaderExit {
    ChildExited,
    Signal,
}

async fn run_foreground(port: u16, name: Option<String>, keep: u16) -> Result<()> {
    use crate::server::static_server;

    let state = StateDir::new()?;
    state.ensure()?;

    cloudflared::ensure_installed()?;

    let (id, name) = start::reserve_entry(
        &state,
        ServiceKind::Hook,
        None,
        format!("hook-{port}"),
        port,
        name,
        std::process::id(),
        true,
        Default::default(),
    )?;

    let _entry = start::EntryGuard::new(state.clone(), id);

    let tunnel_log = state.tunnel_log(&name);
    let log_writer = Arc::new(Mutex::new(
        crate::fsutil::open_private_append_async(&tunnel_log)
            .await
            .with_context(|| format!("opening tunnel log {}", tunnel_log.display()))?,
    ));

    #[cfg(unix)]
    let mut sig_term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    let hook_log = open_hook_log(&state, &name, keep).await?;
    let router = hook_server::router(hook_log);
    let mut server_handle = tokio::spawn(async move {
        if let Err(e) = static_server::serve(router, port).await {
            tracing::error!(%e, "hook server exited with error");
        }
    });

    let mut child = match cloudflared::spawn(port) {
        Ok(c) => c,
        Err(e) => {
            server_handle.abort();
            return Err(e);
        }
    };
    let tunnel_pid = child.id();

    let found = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    if let Some(out) = child.stdout.take() {
        tasks.push(tokio::spawn(start::drain_and_announce(
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
        tasks.push(tokio::spawn(start::drain_and_announce(
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

    if matches!(exit_reason, ReaderExit::Signal) {
        cloudflared::shutdown(tunnel_pid, &mut child).await;
    }

    for task in tasks {
        task.abort();
    }

    match tokio::time::timeout(start::SERVER_SHUTDOWN_TIMEOUT, &mut server_handle).await {
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(
                "hook server did not drain within {:?}, aborting",
                start::SERVER_SHUTDOWN_TIMEOUT
            );
            server_handle.abort();
        }
    }

    Ok(())
}
