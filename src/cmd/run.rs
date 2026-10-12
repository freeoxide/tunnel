//! The RUN command: `ft run --port <p> -- <command>` spawns the command,
//! waits for it to listen, then registers a worker owning BOTH the command
//! child and the tunnel; on timeout everything is torn down, nothing stays.

use std::ffi::OsString;
use std::time::Instant;

use anyhow::{bail, ensure};

use super::{POLL_INTERVAL, POLL_TIMEOUT, doctor, start};
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

    ensure!(
        port::is_port_free(port),
        "port {port} is already in use — the command ft spawns must be able to \
         bind it (is another instance of your server still running?)"
    );

    if foreground {
        crate::cmd::start::run_foreground_with_command(name, Some(port), command).await
    } else {
        run_background(port, name, command).await
    }
}

fn command_display(command: &[OsString]) -> String {
    command
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

async fn run_background(port: u16, name: Option<String>, command: &[OsString]) -> Result<()> {
    let state = StateDir::new()?;

    // Looked up BEFORE reserving: a missing binary leaves no half-started entry.
    cloudflared::ensure_installed()?;

    state.ensure()?;

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

    let worker_pid = match spawn::spawn_worker_with_command(id, &name, None, port, command) {
        Ok(pid) => pid,
        Err(e) => {
            start::remove_reservation(&state, id);
            return Err(e);
        }
    };
    start::record_worker_pid(&state, id, worker_pid)?;

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

        let new_mtime = std::fs::metadata(&registry_path)
            .and_then(|m| m.modified())
            .ok();
        let snapshot: Option<Option<Service>> = if new_mtime != last_mtime {
            last_mtime = new_mtime;
            Some(Registry::load(&state)?.find(&id.to_string()).cloned())
        } else {
            if !proc::pid_alive(worker_pid) {
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            None
        };

        match snapshot {
            Some(Some(svc)) if svc.public_url.is_some() => {
                origin_up = doctor::origin_alive_async(svc.port).await;
                if origin_up {
                    output::print_started(&svc);
                    return Ok(());
                }
            }
            Some(Some(svc)) if !proc::pid_alive(svc.worker_pid) => {
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            Some(None) => {
                return fail_start(&state, &id, &name, worker_pid, command, origin_up).await;
            }
            _ => {}
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
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
        bail!(
            "'{}' exited before the tunnel came up{reason}",
            command_display(command)
        )
    } else {
        bail!("worker for '{name}' exited before the tunnel came up{reason}")
    }
}

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

    #[test]
    fn command_display_joins_the_argv() {
        assert_eq!(
            command_display(&["npm".into(), "run".into(), "dev".into()]),
            "npm run dev"
        );
    }
}
