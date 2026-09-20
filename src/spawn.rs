//! Detached worker spawning: background starts re-invoke the binary as
//! `ft run-worker ...` in a new session (worker + cloudflared survive the
//! parent exiting); stdout/stderr append to `worker.log`. On Unix a
//! `setsid()` pre_exec makes the child a group leader so `kill(-worker_pid)`
//! reaches the whole tree.

use std::ffi::OsString;
use std::path::Path;

use crate::error::Result;
use crate::state::StateDir;

/// Handshake env value: the worker refuses to run without it, so a direct
/// `ft run-worker` cannot bypass START's validation. Needs to be set, not guessed.
fn worker_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = nanos ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15);
    format!("{mixed:016x}")
}

/// Stand-in for the mandatory `--dir` flag when the worker has no directory
/// (proxy/run/hook; clap rejects empty values). The worker never reads it for
/// those kinds; a mis-tagged Static invocation fails closed on the
/// unresolvable path.
pub(crate) const PROXY_DIR_SENTINEL: &str = "/ft-proxy-has-no-directory";

/// The run-worker argv prefix. The Drop token does NOT ride the argv (`ps`
/// visibility) — the worker reads it from the private token file.
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

/// Spawn the detached STATIC (or directory-less) worker; the detachment
/// contract is [`spawn_worker_with_command`]'s.
pub fn spawn_worker(id: u64, name: &str, dir: Option<&Path>, port: u16) -> Result<u32> {
    spawn_worker_full(id, name, dir, port, &[], None, None)
}

/// Spawn the HOOK worker: directory-less, carrying the retention value the
/// worker applies to its request store.
pub fn spawn_hook_worker(id: u64, name: &str, port: u16, keep: u16) -> Result<u32> {
    spawn_worker_full(id, name, None, port, &[], Some(keep), None)
}

/// Spawn the DROP worker: argv carries the upload target (re-checked by the
/// worker) and the cap; the token travels via the private file, never argv.
pub fn spawn_drop_worker(id: u64, name: &str, dir: &Path, port: u16, max_size: u64) -> Result<u32> {
    spawn_worker_full(id, name, Some(dir), port, &[], None, Some(max_size))
}

/// Spawn the detached run-worker with `command`: fresh group + session, logs
/// appended, not awaited, no kill_on_drop — it outlives the parent.
pub fn spawn_worker_with_command(
    id: u64,
    name: &str,
    dir: Option<&Path>,
    port: u16,
    command: &[OsString],
) -> Result<u32> {
    spawn_worker_full(id, name, dir, port, command, None, None)
}

/// Platform-neutral spawn setup (log handles, exe, argv, FT_WORKER_TOKEN,
/// stdio) — shared so the platform variants cannot drift.
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

/// The single spawn path: wrappers pin their unused optionals so historical
/// argv shapes stay byte-identical (hook adds only --keep, drop --max-size).
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

    // setsid(): pgid = pid, so kill(-worker_pid) reaches the whole tree. NO
    // process_group(0) as well — std's setpgid would run first and make
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

/// Windows: detached, own group, no console; the worker's Job Object
/// ([`crate::worker::run`]) cascades its kill to the tree.
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
