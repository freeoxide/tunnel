//! The RUN command.
//!
//! `ft run --port <port> -- <command>` spawns the operator's command, waits
//! for it to accept connections on the port, then registers the result like
//! any other service: a detached worker owns BOTH the command child and the
//! Quick Tunnel pointing at it (PROXY otherwise). The port wait can only run
//! AFTER the child exists (the child IS the server): a friendly "never came
//! up" with the captured output beats a tunnel that 502s; on timeout the
//! worker's group is torn down (relayed to the command's group) — a failed
//! run leaves nothing running. No `--yes`: no directory to confirm; the port
//! must be free (the child has to bind it).

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use anyhow::{bail, ensure};

use super::{POLL_INTERVAL, POLL_TIMEOUT, PROBE_TIMEOUT, start};
use crate::cloudflared;
use crate::error::Result;
use crate::model::{Registry, Service, ServiceKind};
use crate::output;
use crate::port;
use crate::proc;
use crate::spawn;
use crate::state::StateDir;

pub async fn run(
    port: u16,
    name: Option<String>,
    foreground: bool,
    command: &[OsString],
) -> Result<()> {
    // Refuse before touching any state: clap parses a trailing `--` with
    // nothing after it, so this check is what keeps it a usage error.
    ensure!(
        !command.is_empty(),
        "no command given after `--` — pass the command to run and tunnel, e.g. \
         `ft run --port 3000 -- npm start`"
    );

    // The child has to BIND the port (unlike PROXY's existing upstream), so
    // an occupied one is a friendly up-front failure.
    ensure!(
        port::is_port_free(port),
        "port {port} is already in use — the command ft spawns must be able to \
         bind it (is another instance of your server still running?)"
    );

    if foreground {
        // No port-wait in the foreground: the operator watches the command
        // live; the "never came up" surface is the command exiting.
        crate::cmd::start::run_foreground_with_command(name, Some(port), command).await
    } else {
        run_background(port, name, command).await
    }
}

/// Async twin of `doctor::origin_alive` — this runs inside the poll loop,
/// where a blocking connect would stall the runtime. Loopback-only by build.
async fn origin_ready(port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// The full argv, lossily joined — the message must never fail on a weird byte.
fn command_display(command: &[OsString]) -> String {
    command
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Background flow: reserve, spawn the worker (command in its argv), poll for
/// URL AND port — cloudflared connects lazily: "running" means listening.
async fn run_background(port: u16, name: Option<String>, command: &[OsString]) -> Result<()> {
    let state = StateDir::new()?;

    // --- cloudflared ------------------------------------------------------
    // Looked up BEFORE reserving: a missing binary leaves no half-started entry.
    cloudflared::ensure_installed()?;

    state.ensure()?;

    // --- Reserve name + id + entry atomically -----------------------------
    // Shared reservation incl. START_GRACE; the command pid lands later
    // (the worker spawns it and records `command_pid`).
    let (id, name) = start::reserve_entry(
        &state,
        ServiceKind::Run,
        None,
        format!("run-{port}"),
        port,
        name,
        0,
        false,
        Default::default(),
    )?;

    // --- Spawn worker -----------------------------------------------------
    // `dir: None` = directory-less worker; the command rides the argv
    // after `--`, read only by a Run worker.
    let worker_pid = match spawn::spawn_worker_with_command(id, &name, None, port, command) {
        Ok(pid) => pid,
        Err(e) => {
            start::remove_reservation(&state, id);
            return Err(e);
        }
    };
    start::record_worker_pid(&state, id, worker_pid)?;

    // --- Poll for the tunnel URL and the command's port -------------------
    // Shared mtime-gated loop + one extra condition: cloudflared connects
    // lazily — the command must actually be listening.
    let registry_path = state.registry_path();
    let mut last_mtime = std::fs::metadata(&registry_path)
        .and_then(|m| m.modified())
        .ok();
    let deadline = Instant::now() + POLL_TIMEOUT;
    let mut origin_up = false;
    loop {
        if Instant::now() >= deadline {
            break;
        }

        // Cheap stat first; re-read+parse only when the file changed.
        let new_mtime = std::fs::metadata(&registry_path)
            .and_then(|m| m.modified())
            .ok();
        // `None` = did NOT re-read this poll (mtime unchanged); `Some(None)`
        // = re-read and our entry is gone (vanished).
        let snapshot: Option<Option<Service>> = if new_mtime != last_mtime {
            last_mtime = new_mtime;
            Some(Registry::load(&state)?.find(&id.to_string()).cloned())
        } else {
            // Registry unchanged: probe the recorded pid directly to keep
            // fail-fast (the worker may have died silently between rewrites).
            if !proc::pid_alive(worker_pid) {
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                // The URL alone is not success for a run: the origin (the
                // command's port) must answer too.
                origin_up = origin_ready(svc.port).await;
                if origin_up {
                    output::print_started(&svc);
                    return Ok(());
                }
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                // Worker died before publishing — surface the reason inline
                // (the entry is removed; `ft logs` won't exist afterwards).
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            Some(None) => {
                // Our entry vanished — concurrent `ft kill` or the worker's
                // own self-remove; tear down, don't poll 30 s with an orphan.
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            // Still starting, or unchanged registry: poll again.
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    // Timed out: tear everything down (group kill + relay to the command's
    // group); the message names WHICH half never arrived.
    start::teardown(&state, id, worker_pid, "URL timeout").await;
    let reason = last_reason(&state, &name);
    if origin_up {
        bail!("timed out waiting for the tunnel URL{reason}")
    } else {
        bail!(
            "'{}' never started listening on 127.0.0.1:{port} — the server never \
             came up, so no tunnel was left behind{reason}",
            command_display(command)
        )
    }
}

/// The poll loop's fail-fast arm (worker death, vanished entry): teardown +
/// a reason that for a run is usually the command's own output.
async fn fail_start(
    state: &StateDir,
    id: &u64,
    name: &str,
    worker_pid: u32,
    command: &[OsString],
    origin_up: bool,
) -> Result<()> {
    start::teardown(state, *id, worker_pid, "worker death").await;
    let reason = last_reason(state, name);
    if origin_up {
        // The port WAS answering; its death is the command exiting — same
        // message shape, the operator's next step is the same.
        bail!(
            "'{}' exited before the tunnel came up{reason}",
            command_display(command)
        )
    } else {
        bail!("worker for '{name}' exited before the tunnel came up{reason}")
    }
}

/// Like the shared `start::last_reason` but `worker.log` FIRST: a run's
/// interesting failure is almost always the command's own captured output.
fn last_reason(state: &StateDir, name: &str) -> String {
    let pick = [state.worker_log(name), state.tunnel_log(name)]
        .into_iter()
        .find_map(|p| start::last_line(&p));
    match pick {
        Some(line) => format!(":\n  {line}"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn origin_ready_accepts_a_live_listener() {
        // Loopback-only sockets: no external network is touched.
        let listener =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        assert!(
            origin_ready(port).await,
            "a live listener must read as ready"
        );
    }

    #[tokio::test]
    async fn origin_ready_rejects_a_dead_port() {
        // Bind then drop the listener: nothing else grabs that exact
        // ephemeral port in between (same technique as cmd/doctor.rs).
        let port = {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("bind loopback listener");
            let p = listener.local_addr().expect("local addr").port();
            drop(listener);
            p
        };
        assert!(
            !origin_ready(port).await,
            "a closed port must read as not ready (the never-came-up trigger)"
        );
    }

    #[test]
    fn command_display_joins_the_argv() {
        // Error messages quote the operator's command back to them; the join
        // must keep every argument in order.
        assert_eq!(
            command_display(&["npm".into(), "run".into(), "dev".into()]),
            "npm run dev"
        );
    }
}
