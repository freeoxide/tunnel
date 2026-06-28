//! Detached worker process spawning.
//!
//! The background START flow does not run the worker in-process; instead it
//! re-invokes the current binary as `ft run-worker ...` in a new session so
//! that the worker (and its `cloudflared` child) survive the parent `ft`
//! process exiting. The worker's stdout/stderr are redirected to its
//! `worker.log` so the parent can return immediately and the user can inspect
//! output later via `ft logs`.
//!
//! Spawning follows the standard Unix detach pattern via `process_group(0)`
//! plus a `setsid()` `pre_exec`: the child becomes its own session leader and
//! the leader of a fresh process group whose id equals its pid. That lets
//! `kill_process_group(worker_pid)` later reach the worker and everything it
//! spawned.

use std::fs::OpenOptions;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::Result;
use crate::state::StateDir;
use anyhow::Context;

/// Spawn the detached `run-worker` child for a service and return its pid.
///
/// The child is given a fresh process group and session, its stdin is wired to
/// `/dev/null`, and its stdout + stderr are both pointed at the service's
/// `worker.log` (opened in append mode so restarts accumulate rather than
/// clobber). The child is intentionally *not* awaited and `kill_on_drop` is
/// left disabled so it keeps running after this function returns and after the
/// parent process exits.
pub fn spawn_worker(id: u64, name: &str, dir: &Path, port: u16) -> Result<u32> {
    let state = StateDir::new()?;
    let worker_log = state.worker_log(name);

    // Open the log file twice so stdout and stderr each get an owned handle
    // that the child can dup. Append (and create) so restarts are additive.
    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&worker_log)
        .with_context(|| format!("opening worker log {}", worker_log.display()))?;
    let stderr_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&worker_log)
        .with_context(|| format!("opening worker log {}", worker_log.display()))?;

    let exe = std::env::current_exe()
        .context("locating the current executable to spawn the worker")?;

    let mut cmd = Command::new(exe);
    cmd.args([
        "run-worker",
        "--id",
        &id.to_string(),
        "--name",
        name,
        "--dir",
        &dir.to_string_lossy(),
        "--port",
        &port.to_string(),
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::from(stdout_file))
    .stderr(Stdio::from(stderr_file));

    // New session via setsid(): the child becomes a session leader AND the
    // leader of a fresh process group whose id equals its pid — so a later
    // kill(-worker_pid) reaches the whole tree, including cloudflared, which
    // inherits this group. We deliberately do NOT also call process_group(0):
    // std applies that (via setpgid) before pre_exec, which would make the
    // child a group leader first and cause setsid() to fail with EPERM. The
    // error is propagated rather than swallowed so a failure to detach is loud.
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("setsid failed: {e}")))
                .map(|_| ())
        });
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("spawning worker for service '{name}'"))?;

    // Intentionally do NOT wait, and do NOT set kill_on_drop: the worker must
    // outlive this process. Return the child's pid for the registry. On Unix a
    // freshly spawned child always has a pid.
    let pid = child.id();

    // Drop without reaping so the worker is not killed when this handle goes
    // away; the child keeps running in its own session/process group.
    std::mem::forget(child);

    Ok(pid)
}
