//! Detached worker process spawning.
//!
//! The background start flows re-invoke the current binary as
//! `ft run-worker ...` in a new session, so the worker (and its `cloudflared`
//! child) survive the parent `ft` exiting. The worker's stdout/stderr are
//! redirected to its `worker.log` (readable later via `ft logs`). On Unix the
//! child is made a session/process-group leader via a `setsid()` `pre_exec`,
//! so `kill(-worker_pid)` later reaches the worker and everything it spawned.

use std::ffi::OsString;
use std::path::Path;

use crate::error::Result;
use crate::state::StateDir;

/// A best-effort handshake value handed to the spawned worker via its
/// environment: the worker refuses to run without it, so `ft run-worker`
/// cannot be invoked directly to bypass START's validation. A local handshake,
/// not a network secret — it only needs to be *set*, never guessed.
fn worker_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = nanos ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15);
    format!("{mixed:016x}")
}

/// Stand-in value for the mandatory `--dir` flag when spawning a worker that
/// has no directory (proxy/run/hook). clap rejects empty flag values, so such
/// workers pass this deliberately non-existent path; the worker never reads it
/// for those kinds (their spec comes from the registry entry), and a
/// hand-crafted direct invocation against a mis-tagged `Static` entry fails
/// closed: `resolve_dir` refuses the path, `is_sensitive_dir` fail-closes on
/// the unresolvable one.
pub(crate) const PROXY_DIR_SENTINEL: &str = "/ft-proxy-has-no-directory";

/// The `run-worker` argv prefix shared by the Unix and Windows spawn paths:
/// `--dir` is the served/upload-target directory or [`PROXY_DIR_SENTINEL`];
/// the Run worker's `command` rides after a trailing `--` (flag-looking child
/// args are never parsed as worker flags); `keep`/`max_size` are the Hook/Drop
/// runtime knobs (`None` for other kinds — the registry carries no fields for
/// them). The Drop token deliberately does NOT ride the argv (`ps`
/// visibility): the worker reads it from the service's private token file.
fn run_worker_args(
    id: u64,
    name: &str,
    dir: Option<&Path>,
    port: u16,
    command: &[OsString],
    keep: Option<u16>,
    max_size: Option<u64>,
) -> Vec<OsString> {
    let dir_arg = dir
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| PROXY_DIR_SENTINEL.to_string());
    let mut args: Vec<OsString> = vec![
        "run-worker".into(),
        "--id".into(),
        id.to_string().into(),
        "--name".into(),
        name.into(),
        "--dir".into(),
        dir_arg.into(),
        "--port".into(),
        port.to_string().into(),
    ];
    if let Some(keep) = keep {
        args.push("--keep".into());
        args.push(keep.to_string().into());
    }
    if let Some(max_size) = max_size {
        args.push("--max-size".into());
        args.push(max_size.to_string().into());
    }
    if !command.is_empty() {
        args.push("--".into());
        args.extend(command.iter().cloned());
    }
    args
}

/// Spawn the detached `run-worker` child for a service and return its pid.
///
/// `dir: None` spawns a worker that fronts a port rather than a directory
/// (proxy, or run whose child is passed separately); `dir: Some(_)` spawns the
/// usual STATIC worker. See [`spawn_worker_with_command`] for the detachment
/// contract; this wrapper covers the flows that never spawn a command child.
pub fn spawn_worker(id: u64, name: &str, dir: Option<&Path>, port: u16) -> Result<u32> {
    spawn_worker_full(id, name, dir, port, &[], None, None)
}

/// Spawn the detached `run-worker` child for a HOOK service and return its
/// pid: directory-less (the hook origin has no served tree) and carrying the
/// retention value the worker applies to its request store.
pub fn spawn_hook_worker(id: u64, name: &str, port: u16, keep: u16) -> Result<u32> {
    spawn_worker_full(id, name, None, port, &[], Some(keep), None)
}

/// Spawn the detached `run-worker` child for a DROP service and return its
/// pid: the argv carries the upload target directory (the worker re-resolves
/// and re-checks it) and the per-upload cap, while the access token travels
/// via the service's private token file — never the argv (`ps` visibility).
pub fn spawn_drop_worker(id: u64, name: &str, dir: &Path, port: u16, max_size: u64) -> Result<u32> {
    spawn_worker_full(id, name, Some(dir), port, &[], None, Some(max_size))
}

/// Spawn the detached `run-worker` child for a service and return its pid,
/// passing `command` (the `ft run -- <command>` child) to the worker. Fresh
/// process group and session; stdin `/dev/null`; stdout+stderr appended to
/// the service's `worker.log`. Not awaited and no `kill_on_drop`, so it keeps
/// running after the parent exits.
pub fn spawn_worker_with_command(
    id: u64,
    name: &str,
    dir: Option<&Path>,
    port: u16,
    command: &[OsString],
) -> Result<u32> {
    spawn_worker_full(id, name, dir, port, command, None, None)
}

/// The platform-neutral setup behind every spawn: open the worker log twice
/// (owned stdout/stderr handles, append+create so restarts are additive, 0600
/// on Unix — the log can carry request/paths detail), resolve the current
/// executable, and wire the argv, the `FT_WORKER_TOKEN` handshake env, and
/// the stdio. The platform-specific detachment is layered on by the
/// `spawn_worker_full` variants, which share this builder so their setup
/// cannot drift apart.
fn worker_command(
    id: u64,
    name: &str,
    dir: Option<&Path>,
    port: u16,
    command: &[OsString],
    keep: Option<u16>,
    max_size: Option<u64>,
) -> Result<std::process::Command> {
    use std::process::{Command, Stdio};

    use anyhow::Context;

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
    cmd.args(run_worker_args(
        id, name, dir, port, command, keep, max_size,
    ))
    .env("FT_WORKER_TOKEN", &token)
    .stdin(Stdio::null())
    .stdout(Stdio::from(stdout_file))
    .stderr(Stdio::from(stderr_file));
    Ok(cmd)
}

/// The single spawn path behind every entry point: each public wrapper pins
/// the optional values its flow does not use (`command` empty / `keep` and
/// `max_size` None), so historical argv shapes stay byte-identical while the
/// hook flow adds only `--keep` and the drop flow only `--max-size`.
#[cfg(unix)]
fn spawn_worker_full(
    id: u64,
    name: &str,
    dir: Option<&Path>,
    port: u16,
    command: &[OsString],
    keep: Option<u16>,
    max_size: Option<u64>,
) -> Result<u32> {
    use std::os::unix::process::CommandExt;

    use anyhow::Context;

    let mut cmd = worker_command(id, name, dir, port, command, keep, max_size)?;

    // New session via setsid(): the child becomes a session/group leader
    // (pgid = pid), so a later kill(-worker_pid) reaches the whole tree.
    // NO process_group(0) as well: std applies that (setpgid) before
    // pre_exec, which would make the child a group leader first and make
    // setsid() fail with EPERM. Errors propagate so a failed detach is loud.
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

    // Intentionally no wait and no kill_on_drop: the worker must outlive this
    // process. On Unix a freshly spawned child always has a pid.
    let pid = child.id();

    // Drop without reaping: the child keeps running in its own session.
    std::mem::forget(child);

    Ok(pid)
}

/// Windows: spawn the `run-worker` child detached, in its own process group
/// with no console, so it survives the parent `ft` exiting; stdout/stderr go
/// to the service's `worker.log`. The worker assigns itself to a Job Object
/// (see [`crate::worker::run`]), so killing the worker cascades to its tree
/// and a hard-killed worker still reaps it.
#[cfg(windows)]
fn spawn_worker_full(
    id: u64,
    name: &str,
    dir: Option<&Path>,
    port: u16,
    command: &[OsString],
    keep: Option<u16>,
    max_size: Option<u64>,
) -> Result<u32> {
    use std::os::windows::process::CommandExt;

    use anyhow::Context;

    // Own group so Ctrl-C in the parent's console cannot reach it; no
    // inherited/created console.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0004;

    let mut cmd = worker_command(id, name, dir, port, command, keep, max_size)?;
    cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);

    let pid = cmd
        .spawn()
        .with_context(|| format!("spawning worker for service '{name}'"))?
        .id();
    // The std::process::Child handle drops here without `kill_on_drop`, so the
    // detached worker keeps running; only its pid is recorded in the registry.
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::{PROXY_DIR_SENTINEL, run_worker_args};
    use std::ffi::OsString;
    use std::path::Path;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn static_worker_passes_the_real_directory() {
        let args = run_worker_args(
            7,
            "blog",
            Some(Path::new("/srv/blog")),
            8000,
            &[],
            None,
            None,
        );
        assert_eq!(
            args,
            os(&[
                "run-worker",
                "--id",
                "7",
                "--name",
                "blog",
                "--dir",
                "/srv/blog",
                "--port",
                "8000",
            ])
        );
    }

    #[test]
    fn proxy_worker_passes_the_sentinel_directory() {
        // A proxy worker has no directory: the mandatory `--dir` flag carries
        // the sentinel, and the worker takes its real spec from the registry.
        let args = run_worker_args(9, "api", None, 3000, &[], None, None);
        assert_eq!(
            args,
            os(&[
                "run-worker",
                "--id",
                "9",
                "--name",
                "api",
                "--dir",
                PROXY_DIR_SENTINEL,
                "--port",
                "3000",
            ])
        );
        // The sentinel must never name an existing path: a mis-tagged Static
        // worker has to fail closed on it, not serve some real directory.
        assert!(!std::path::Path::new(PROXY_DIR_SENTINEL).exists());
    }

    #[test]
    fn run_worker_carries_the_child_command_after_a_separator() {
        // The separator is load-bearing: flag-looking child args must reach
        // the child verbatim, not run-worker's own clap definition.
        let args = run_worker_args(
            11,
            "dev",
            None,
            3000,
            &os(&["npm", "run", "dev", "--verbose"]),
            None,
            None,
        );
        assert_eq!(
            args,
            os(&[
                "run-worker",
                "--id",
                "11",
                "--name",
                "dev",
                "--dir",
                PROXY_DIR_SENTINEL,
                "--port",
                "3000",
                "--",
                "npm",
                "run",
                "dev",
                "--verbose",
            ])
        );
    }

    #[test]
    fn hook_worker_carries_its_retention_flag_before_the_separator() {
        // `--keep` belongs to run-worker's own clap definition, so it sits
        // BEFORE the `--` separator (after it, everything is the child's).
        let args = run_worker_args(12, "gh", None, 9000, &[], Some(50), None);
        assert_eq!(
            args,
            os(&[
                "run-worker",
                "--id",
                "12",
                "--name",
                "gh",
                "--dir",
                PROXY_DIR_SENTINEL,
                "--port",
                "9000",
                "--keep",
                "50",
            ])
        );
    }

    #[test]
    fn drop_worker_carries_its_directory_and_cap_before_the_separator() {
        // The REAL upload target (unlike the directory-less kinds) and the
        // cap flag before `--`; the access token appears NOWHERE in the argv.
        let args = run_worker_args(
            13,
            "share",
            Some(Path::new("/srv/inbox")),
            9001,
            &[],
            None,
            Some(4096),
        );
        assert_eq!(
            args,
            os(&[
                "run-worker",
                "--id",
                "13",
                "--name",
                "share",
                "--dir",
                "/srv/inbox",
                "--port",
                "9001",
                "--max-size",
                "4096",
            ])
        );
    }
}
