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

use std::path::Path;

use crate::error::Result;
use crate::state::StateDir;

/// A best-effort handshake value handed to the spawned worker via its
/// environment. The worker refuses to run without it ([`crate::worker::run`]),
/// so `ft run-worker` cannot be invoked directly to bypass the START command's
/// input validation and sensitive-directory confirmation. This is a local
/// handshake (not a network secret): the value only needs to be *set* by
/// `spawn_worker`, never guessed.
fn worker_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = nanos ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15);
    format!("{mixed:016x}")
}

/// Spawn the detached `run-worker` child for a service and return its pid.
///
/// The child is given a fresh process group and session, its stdin is wired to
/// `/dev/null`, and its stdout + stderr are both pointed at the service's
/// `worker.log` (opened in append mode so restarts accumulate rather than
/// clobber). The child is intentionally *not* awaited and `kill_on_drop` is
/// left disabled so it keeps running after this function returns and after the
/// parent process exits.
#[cfg(unix)]
pub fn spawn_worker(id: u64, name: &str, dir: &Path, port: u16) -> Result<u32> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use anyhow::Context;

    let state = StateDir::new()?;
    let worker_log = state.worker_log(name);

    // Open the log file twice so stdout and stderr each get an owned handle
    // that the child can dup. Append (and create) so restarts are additive.
    // Mode 0600: the worker log can contain request/paths detail.
    let stdout_file = crate::fsutil::open_private_append(&worker_log)
        .with_context(|| format!("opening worker log {}", worker_log.display()))?;
    let stderr_file = crate::fsutil::open_private_append(&worker_log)
        .with_context(|| format!("opening worker log {}", worker_log.display()))?;

    let exe =
        std::env::current_exe().context("locating the current executable to spawn the worker")?;

    let token = worker_token();
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
    .env("FT_WORKER_TOKEN", &token)
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
                .map_err(|e| std::io::Error::other(format!("setsid failed: {e}")))
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

/// Windows: spawn the `run-worker` child detached, in its own process group
/// with no console, so it survives the parent `ft` exiting. Its stdout/stderr
/// are pointed at the service's `worker.log` (append, mode-inherited). The
/// worker assigns itself to a Job Object (see [`crate::worker::run`]), so
/// `kill`-the-worker cascades to cloudflared and a hard-killed worker still
/// reaps its tree.
#[cfg(windows)]
pub fn spawn_worker(id: u64, name: &str, dir: &Path, port: u16) -> Result<u32> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    use anyhow::Context;

    // CREATE_NEW_PROCESS_GROUP: the worker gets its own group so Ctrl-C in the
    // parent's console does not reach it (it must outlive the parent).
    // DETACHED_PROCESS: the worker does not inherit (or create) a console.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0004;

    let state = StateDir::new()?;
    let worker_log = state.worker_log(name);
    let stdout_file = crate::fsutil::open_private_append(&worker_log)
        .with_context(|| format!("opening worker log {}", worker_log.display()))?;
    let stderr_file = crate::fsutil::open_private_append(&worker_log)
        .with_context(|| format!("opening worker log {}", worker_log.display()))?;

    let exe =
        std::env::current_exe().context("locating the current executable to spawn the worker")?;

    let token = worker_token();
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
    .env("FT_WORKER_TOKEN", &token)
    .creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS)
    .stdin(Stdio::null())
    .stdout(Stdio::from(stdout_file))
    .stderr(Stdio::from(stderr_file));

    let pid = cmd
        .spawn()
        .with_context(|| format!("spawning worker for service '{name}'"))?
        .id();
    // The std::process::Child handle drops here without `kill_on_drop`, so the
    // detached worker keeps running; only its pid is recorded in the registry.
    Ok(pid)
}
