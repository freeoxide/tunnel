//! Process introspection and signaling helpers.
//!
//! Two kinds of probes:
//! - [`pid_matches`] / [`pid_alive`]: a *cmdline-aware* identity check that
//!   defeats PID reuse — a recycled pid will not contain the needle
//!   (`run-worker` / `cloudflared`), so it is never mistaken for ours or
//!   signalled. Linux reads `/proc/<pid>/cmdline`; macOS reads the args via
//!   `sysctl(KERN_PROCARGS2)`; Windows checks the process image name
//!   (`ft.exe`/`cloudflared.exe`) via `QueryFullProcessImageNameW`; other Unix
//!   falls back to a signal-0 liveness probe (identity best-effort there).
//! - [`process_exists`]: a plain liveness check with no needle, used for
//!   foreground services (whose `ft` cmdline lacks the `run-worker` token).
//!
//! Signalling: Unix uses `SIGTERM`→grace→`SIGKILL` on a process group
//! (`kill(-pgid)`). Windows terminates a single process via `TerminateProcess`
//! — the detached worker owns a Job Object (`KILL_ON_JOB_CLOSE`), so
//! terminating the worker cascades to its whole tree (cloudflared), matching
//! the Unix group kill. A spawned command child additionally leads its OWN
//! process group (`own_process_group`), so the worker's exit paths can killpg
//! the whole command subtree without ever signalling the worker's group.

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;
use tokio::process::{Child, Command};

// --- run-service command children -------------------------------------------
//
// A `Run` service's origin is a command `ft` itself spawns (the operator's
// dev server). The worker and foreground flows share the discipline below:
// Linux adds PR_SET_PDEATHSIG against a SIGKILL'd spawner; Windows relies on
// the worker's KILL_ON_JOB_CLOSE Job Object. Unlike cloudflared, the command
// child leads its OWN process group (`own_process_group`), so teardown can
// killpg the entire command subtree (child + grandchildren like
// `npm run dev` -> vite) without ever signalling the spawner's group (the
// worker + cloudflared when detached; the operator's shell in the foreground).

/// Spawn the user's command child with `PORT=port` exported, so well-behaved
/// dev servers pick their port up from the environment. stdout/stderr are
/// piped (teed into `worker.log` by the caller), stdin is null. On Unix the
/// child leads its own process group (see [`own_process_group`]), which is
/// what lets [`shutdown_child_command`] take the whole subtree down.
pub(crate) fn spawn_command_child(
    command: &[std::ffi::OsString],
    port: u16,
) -> crate::error::Result<Child> {
    use anyhow::Context;

    // clap already refuses an empty `--` tail at the CLI layer; this is the
    // defense-in-depth for direct internal callers.
    let Some((bin, args)) = command.split_first() else {
        anyhow::bail!("cannot spawn an empty command");
    };
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("PORT", port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Group isolation (R3-1): without this the child inherits the spawner's
    // group and no safe group signal could reach the grandchildren. Fatal
    // rather than best-effort: a non-leader child would make killpg teardown
    // target a group that is not exclusively the command subtree's.
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(own_process_group);
    }

    // On Linux, SIGKILL the child if its spawner dies — even via SIGKILL/OOM
    // — so the command never outlives its tunnel. Shared hook with
    // `cloudflared::spawn` (see [`parent_death_signal`]).
    #[cfg(target_os = "linux")]
    unsafe {
        cmd.pre_exec(parent_death_signal);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn command {bin:?}"))?;
    Ok(child)
}

/// Unix-only pre-exec hook: make the (pre-exec) child a process-group leader,
/// so its pgid equals its pid and `killpg(child_pid)` later reaches exactly
/// the command subtree. The pre-exec window is the only safe place — the child
/// has not yet exec'd into arbitrary operator code.
#[cfg(unix)]
fn own_process_group() -> Result<(), std::io::Error> {
    // setpgid(0, 0) moves this not-yet-exec'd child into a fresh group of its
    // own; nix wraps the syscall, no unsafe needed.
    nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0))
        .map_err(|e| std::io::Error::other(format!("setpgid failed: {e}")))
}

/// Linux-only pre-exec hook: request SIGKILL on parent death and refuse to
/// exec if the parent is ALREADY gone (reparented to init). Named `pub(crate)`
/// so both pre-exec sites — the command child and `cloudflared::spawn` —
/// share ONE implementation of the fork→prctl race handling.
#[cfg(target_os = "linux")]
pub(crate) fn parent_death_signal() -> Result<(), std::io::Error> {
    // SAFETY: prctl sets a kernel attribute on this (pre-exec) process;
    // getppid is a plain read. A failed prctl is surfaced — silently exec'ing
    // without the death signal is exactly what the hook must prevent.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::getppid() == 1 {
            return Err(std::io::Error::other(
                "parent died before prctl(PR_SET_PDEATHSIG); refusing to exec",
            ));
        }
    }
    Ok(())
}

/// Move a freshly spawned command child into a background task that awaits
/// (and thereby reaps) it. The keep-alive `select!` needs a child-exit arm
/// while teardown needs to signal by pid — impossible while tokio's `Child`
/// is borrowed by a `wait()`. The monitor owns the handle; the spawner keeps
/// the bare pid; [`shutdown_child_command`] coordinates the two.
pub(crate) fn spawn_wait_monitor(mut child: Child) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = child.wait().await;
    })
}

/// Grace before a SIGTERM'd command child is SIGKILL'd (Unix). Slightly longer
/// than cloudflared's: dev servers often flush state on TERM.
#[cfg(unix)]
const CHILD_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// The never-completing monitor stand-in for flows that spawn no command
/// child (static/proxy workers, non-run foreground): the `select!` needs a
/// monitor binding, and [`shutdown_child_command`] treats the pid-less call
/// as its bounded no-op. One shared constructor so the placeholder the tests
/// pin is exactly what production uses.
pub(crate) fn command_monitor_placeholder() -> tokio::task::JoinHandle<()> {
    tokio::spawn(std::future::pending())
}

/// Tear down the spawned command child — the counterpart of
/// [`spawn_wait_monitor`].
///
/// `pid == None` means no child was spawned: the monitor slot holds the
/// never-completing placeholder, so this is a bounded no-op (abort + await —
/// awaiting a pending future would hang every non-Run teardown). With a pid:
/// a finished monitor means the child already exited and was reaped. Unix
/// signals the child's WHOLE process group (it was made a group leader at
/// spawn, so the negative pid covers the direct child AND its grandchildren,
/// R3-1); the group is pinned against pid reuse by the monitor's open
/// `Child` handle (a dead leader's group survives while members remain).
/// Windows terminates by pid — sound without an identity needle because the
/// open handle pins the pid until this call aborts it — and the worker's Job
/// Object additionally reaps the whole tree on exit.
pub(crate) async fn shutdown_child_command(
    pid: Option<u32>,
    monitor: &mut tokio::task::JoinHandle<()>,
) {
    // No child: abort the placeholder (never resolves on its own) and reap
    // the task handle.
    let Some(pid) = pid else {
        monitor.abort();
        let _ = monitor.await;
        return;
    };
    // The monitor already observed and reaped the exit: nothing to do.
    if monitor.is_finished() {
        return;
    }
    #[cfg(unix)]
    {
        // Negative pid = the whole command-subtree group; guarded against
        // pid reuse by the not-yet-reaped monitor handle. Gone members
        // return ESRCH, ignored.
        let group = Pid::from_raw(-(pid as i32));
        let _ = kill(group, Signal::SIGTERM);
        if tokio::time::timeout(CHILD_SHUTDOWN_GRACE, &mut *monitor)
            .await
            .is_err()
        {
            // SIGKILL is un-ignoreable; the monitor is guaranteed still
            // pending here (the timeout only elapses when it did not
            // complete), so the await is bounded.
            let _ = kill(group, Signal::SIGKILL);
            let _ = (&mut *monitor).await;
        }
        // On the Ok arm the timeout's await already reaped the child via the
        // monitor — the handle is consumed and must NOT be polled again.
    }
    #[cfg(windows)]
    {
        windows_proc::terminate_child(pid);
        monitor.abort();
        let _ = monitor.await;
    }
    // No terminate primitive on an unsupported target; still reap the monitor
    // so no task is left dangling.
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        monitor.abort();
        let _ = monitor.await;
    }
}

/// True if process `pid` exists and its command line contains `needle`.
/// Linux reads `/proc/<pid>/cmdline`; macOS `sysctl(KERN_PROCARGS2)`; Windows
/// checks the image-name suffix. All defeat PID reuse. On other Unix there is
/// no portable equivalent, so it falls back to a signal-0 liveness probe and
/// the needle is ignored (identity is Linux/macOS/Windows only).
#[cfg(unix)]
pub fn pid_matches(pid: u32, needle: &str) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        cmdline_contains(pid, needle)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = needle;
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }
}

/// True if one of *our* workers is alive at `pid` (cmdline/image contains
/// `run-worker` / `ft.exe`).
#[cfg(unix)]
pub fn pid_alive(pid: u32) -> bool {
    pid_matches(pid, "run-worker")
}

/// True if a process with `pid` is currently running (no identity check) —
/// for foreground services, whose `ft` cmdline lacks the `"run-worker"` token
/// [`pid_alive`] looks for (`ft kill` still gates on its own identity check
/// before signalling them).
#[cfg(unix)]
pub fn process_exists(pid: u32) -> bool {
    kill(Pid::from_raw(pid as i32), None).is_ok()
}

#[cfg(windows)]
#[allow(clippy::question_mark)] // these fns return bool, so `?` is not applicable
mod windows_proc {
    //! Windows process primitives backed by `windows-sys`.
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    };

    /// Rights we need on a target process: enough to query its image name /
    /// exit code, to wait on it (for liveness), AND to terminate it.
    const ACCESS: u32 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE;

    /// A process exit code meaning "still running" (Win32 `STILL_ACTIVE`).
    /// Documentation only — never used for liveness, because a process that
    /// legitimately exits with 259 would read alive forever (WIN-1).
    /// Liveness is decided by `WaitForSingleObject`.
    #[allow(dead_code)]
    const STILL_ACTIVE: u32 = 259;

    /// Open `pid` for query+terminate, returning a handle the caller must
    /// `CloseHandle`. `None` if the process is gone or inaccessible.
    fn open(pid: u32) -> Option<HANDLE> {
        // SAFETY: `OpenProcess` only queries kernel state. Every call site
        // closes the returned handle before returning.
        unsafe {
            let h = OpenProcess(ACCESS, 0, pid);
            if (h as usize) == 0 { None } else { Some(h) }
        }
    }

    pub fn process_exists(pid: u32) -> bool {
        // Liveness via a non-blocking wait (WIN-1): `GetExitCodeProcess` 259
        // is a sentinel, not a guarantee (a real exit with code 259 reads
        // alive forever); WAIT_TIMEOUT vs WAIT_OBJECT_0 has no such
        // ambiguity.
        unsafe {
            let Some(h) = open(pid) else {
                return false;
            };
            let r = WaitForSingleObject(h, 0);
            let _ = CloseHandle(h);
            r == WAIT_TIMEOUT
        }
    }

    /// Lowercased image path of `pid` (e.g. `c:\users\...\ft.exe`).
    fn image_path(pid: u32) -> Option<String> {
        unsafe {
            let Some(h) = open(pid) else {
                return None;
            };
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
            let _ = CloseHandle(h);
            if ok == 0 {
                return None;
            }
            String::from_utf16(&buf[..len as usize])
                .ok()
                .map(|s| s.to_ascii_lowercase())
        }
    }

    pub fn pid_matches(pid: u32, needle: &str) -> bool {
        // Map the cmdline "needle" concept to a Windows image-name suffix.
        let want = match needle {
            "run-worker" | "--foreground" => "ft.exe",
            "cloudflared" => "cloudflared.exe",
            // An unrecognized needle refuses (WIN-5) rather than degrading to
            // a liveness probe — a mis-typed needle must never gate on the
            // wrong identity. (No debug_assert! — it would panic under
            // `cargo test`, which exercises this path.)
            _ => return false,
        };
        image_path(pid).map(|p| p.ends_with(want)).unwrap_or(false)
    }

    pub fn pid_alive(pid: u32) -> bool {
        pid_matches(pid, "run-worker")
    }

    /// Terminate a single process by pid. Returns true if a termination issued.
    fn terminate(pid: u32) -> bool {
        unsafe {
            let Some(h) = open(pid) else {
                return false;
            };
            let ok = TerminateProcess(h, 1);
            let _ = CloseHandle(h);
            ok != 0
        }
    }

    /// Stop a detached worker: terminate the worker pid; its Job Object then
    /// kills the whole tree (cloudflared). `pgid == 0` means "no worker
    /// recorded" — a no-op.
    pub async fn shutdown_process_group(pgid: u32) {
        if pgid == 0 {
            return;
        }
        if pid_matches(pgid, "run-worker") {
            let _ = terminate(pgid);
        }
    }

    /// Terminate an orphaned cloudflared by pid (gated on identity).
    pub fn terminate_orphan(pid: u32) {
        if pid_matches(pid, "cloudflared") {
            let _ = terminate(pid);
        }
    }

    /// Terminate a spawned command child by pid, WITHOUT an identity needle:
    /// sound because the caller only reaches here while the monitor's open
    /// `Child` handle pins the pid against reuse, and `shutdown_child_command`
    /// checked `is_finished` first.
    pub fn terminate_child(pid: u32) {
        let _ = terminate(pid);
    }

    /// Terminate a foreground `ft` process by pid (gated on identity; never
    /// the group, which would kill the operator's shell).
    pub fn terminate_foreground(pid: u32) {
        if pid_matches(pid, "--foreground") {
            let _ = terminate(pid);
        }
    }

    /// Owned Job Object handle. Dropping closes the handle, which (for a job
    /// created with KILL_ON_JOB_CLOSE) kills every process still in the job.
    pub struct JobGuard(HANDLE);
    impl Drop for JobGuard {
        fn drop(&mut self) {
            // SAFETY: we own this handle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Create a Job Object with KILL_ON_JOB_CLOSE, assign THIS process to it,
    /// and return a guard. Hold it for the worker's lifetime: when the worker
    /// exits for any reason the OS closes the handle and kills the whole job —
    /// the Windows equivalent of `PR_SET_PDEATHSIG`. `None` (after logging) if
    /// setup fails: the worker still runs, but a hard-killed worker will not
    /// auto-reap cloudflared.
    pub fn create_kill_on_close_job() -> Option<JobGuard> {
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: kernel object creation/queries. On failure the handle is
        // closed here; on success ownership moves into the returned guard.
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if (h as usize) == 0 {
                tracing::warn!("CreateJobObjectW failed; worker will not auto-reap on hard kill");
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                tracing::warn!(
                    "SetInformationJobObject failed; worker will not auto-reap on hard kill"
                );
                let _ = CloseHandle(h);
                return None;
            }
            if AssignProcessToJobObject(h, GetCurrentProcess()) == 0 {
                tracing::warn!(
                    "AssignProcessToJobObject failed; worker will not auto-reap on hard kill"
                );
                let _ = CloseHandle(h);
                return None;
            }
            Some(JobGuard(h))
        }
    }
}

// `terminate_child` is deliberately NOT re-exported: its only caller is
// `shutdown_child_command` in this module, and a crate-internal `pub use`
// nothing references warns on the Windows target (invisible to Linux gates).
#[cfg(windows)]
pub use windows_proc::{
    create_kill_on_close_job, pid_alive, pid_matches, process_exists, shutdown_process_group,
    terminate_foreground, terminate_orphan,
};

/// Gracefully tear down a process group: `SIGTERM`, poll for the grace window
/// for it to exit, then `SIGKILL` to guarantee cleanup. Both signals target
/// the whole group (negative pid) and are best-effort (gone members return
/// ESRCH, ignored). The grace window is spent in `tokio::time::sleep`, never
/// blocking the executor.
#[cfg(unix)]
pub async fn shutdown_process_group(pgid: u32) {
    // pgid == 0 means "no group recorded": kill(-0) is kill(0), which
    // signals the CALLER's own group (self-kill). No-op instead.
    if pgid == 0 {
        return;
    }
    // Identity gate (CR-1): the pgid is the worker pid; if the worker died
    // and the kernel recycled that pid into an unrelated group, kill(-pgid)
    // would signal the wrong group. A recycled leader lacks `run-worker` in
    // its cmdline, so refuse to signal it (mirrors the Windows gate).
    if !pid_matches(pgid, "run-worker") {
        tracing::debug!(
            "shutdown_process_group: pgid {} no longer matches run-worker; refusing to signal (recycled-pid guard)",
            pgid
        );
        return;
    }
    let raw = -(pgid as i32);
    let _ = kill(Pid::from_raw(raw), Signal::SIGTERM);
    // Poll group liveness (signal-0 kill returns ESRCH once the group is
    // empty) so we usually return well before the grace elapses.
    let deadline = std::time::Duration::from_millis(1500);
    let step = std::time::Duration::from_millis(50);
    let mut waited = std::time::Duration::ZERO;
    while waited < deadline {
        if kill(Pid::from_raw(raw), None).is_err() {
            return; // group is gone
        }
        tokio::time::sleep(step).await;
        waited += step;
    }
    let _ = kill(Pid::from_raw(raw), Signal::SIGKILL);
}

/// Best-effort `SIGTERM` of a single process by pid. Used by `ft prune`,
/// `ft sanitize`, and `ft kill`'s foreground teardown to reap a `cloudflared`
/// whose worker is already gone (an orphan normally dies via
/// `PR_SET_PDEATHSIG`, but that does not survive a host reboot). The
/// `cloudflared` identity gate lives HERE, immediately before the signal:
/// the callers check [`pid_matches`] at decision time and signal later — in
/// prune/sanitize an entire locked registry save sits between — so a pid
/// recycled in that window must be re-verified, never signalled on the
/// caller's stale say-so.
#[cfg(unix)]
pub fn terminate_orphan(pid: u32) {
    if !pid_matches(pid, "cloudflared") {
        return;
    }
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

/// Best-effort termination of a single FOREGROUND `ft` process by pid — one
/// pid, never a group (a foreground `ft` shares the operator's shell's group,
/// so `kill(-pgid)` would kill the shell). The `--foreground` identity gate
/// lives HERE, immediately before the signal, for the same recycled-pid
/// window [`terminate_orphan`] closes.
#[cfg(unix)]
pub fn terminate_foreground(pid: u32) {
    if !pid_matches(pid, "--foreground") {
        return;
    }
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

/// Read `/proc/<pid>/cmdline` and report whether any argument contains `needle`.
#[cfg(target_os = "linux")]
fn cmdline_contains(pid: u32, needle: &str) -> bool {
    let path = std::path::Path::new("/proc")
        .join(pid.to_string())
        .join("cmdline");
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    bytes.split(|b| *b == 0).any(|arg| {
        std::str::from_utf8(arg)
            .map(|s| s.contains(needle))
            .unwrap_or(false)
    })
}

/// Upper bound on the KERN_PROCARGS2 allocation: a blob this large is not one
/// of our own processes, and capping avoids a multi-MB allocation per probe
/// against a pathologically huge argv/env block (EH-2).
#[cfg(target_os = "macos")]
const MAX_PROCARGS_BYTES: usize = 1024 * 1024;

/// Read another process's command line on macOS via `sysctl(KERN_PROCARGS2)`
/// and report whether any *argv* entry contains `needle`. Layout is
/// `[argc:u32][execpath\0][NUL padding][argv\0...][envv\0...]`; we parse argv
/// boundaries and search ONLY the argv region, never the environment, so the
/// needle cannot collide with a foreign process's env vars (CR-2). Works for
/// same-uid processes without root — all we ever probe.
#[cfg(target_os = "macos")]
fn cmdline_contains(pid: u32, needle: &str) -> bool {
    let mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    // First call: discover the required buffer size.
    let mut size: libc::size_t = 0;
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut libc::c_int,
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size == 0 {
        return false;
    }
    // Cap the allocation (EH-2): over 1 MiB cannot be one of ours — refuse.
    if size > MAX_PROCARGS_BYTES {
        return false;
    }
    // Second call: fetch the blob.
    let mut buf = vec![0u8; size];
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut libc::c_int,
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return false;
    }
    argv_contains(&buf, needle)
}

/// Parse a `KERN_PROCARGS2` blob and report whether any argv entry contains
/// `needle`. Pure helper (unit-testable without a real process): read argc,
/// skip the execpath and NUL padding, walk exactly `argc` NUL-terminated
/// entries — anything past that is envv and is never searched (CR-2).
#[cfg(target_os = "macos")]
fn argv_contains(blob: &[u8], needle: &str) -> bool {
    // Leading 4-byte little-endian argc.
    if blob.len() < 4 {
        return false;
    }
    let argc = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if argc == 0 {
        return false;
    }
    let mut pos = 4;

    // Skip the exec path: the first NUL-terminated string after the argc word.
    let Some(exec_end) = blob[pos..].iter().position(|&b| b == 0) else {
        return false;
    };
    pos += exec_end + 1;

    // Skip alignment padding: real argv entries are non-empty (at least the
    // exec path), so any NUL here is padding.
    while pos < blob.len() && blob[pos] == 0 {
        pos += 1;
    }

    // Walk exactly `argc` NUL-terminated argv entries (argv only — CR-2).
    let needle_bytes = needle.as_bytes();
    for _ in 0..argc {
        if pos >= blob.len() {
            // Truncated blob: every present entry was searched — safe to stop.
            return false;
        }
        let entry_end = blob[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|e| pos + e)
            .unwrap_or(blob.len());
        if memmem(&blob[pos..entry_end], needle_bytes) {
            return true;
        }
        if entry_end >= blob.len() {
            return false;
        }
        pos = entry_end + 1;
    }
    false
}

/// Plain byte substring search (no allocation). `haystack` contains the entry,
/// `needle` is ASCII.
#[cfg(target_os = "macos")]
fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(all(test, unix))]
mod command_child_tests {
    use super::*;
    use std::ffi::OsString;

    /// The `ft run` contract: the spawned command finds its port in `PORT`.
    /// Proven through a real child (a shell echoing `$PORT`) since env
    /// inheritance has no pure seam.
    #[tokio::test]
    async fn command_child_receives_port_in_its_environment() {
        // The listener merely produces a realistic, in-use-looking port.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();

        let child = spawn_command_child(
            &[
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from("echo $PORT"),
            ],
            port,
        )
        .expect("spawn echo child");
        let output = child.wait_with_output().await.expect("wait for child");
        let printed = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            printed.trim(),
            port.to_string(),
            "the child must see PORT={port} in its environment"
        );
    }

    /// The with-child counterpart of the placeholder test: SIGTERM lands,
    /// the monitor reaps the exit, and shutdown completes without needing
    /// the SIGKILL escalation.
    #[tokio::test]
    async fn shutdown_child_command_stops_a_real_child_and_completes() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();

        let child = spawn_command_child(&[OsString::from("sleep"), OsString::from("30")], port)
            .expect("spawn sleep child");
        let pid = child.id();
        let mut monitor = spawn_wait_monitor(child);

        let started = std::time::Instant::now();
        shutdown_child_command(pid, &mut monitor).await;
        assert!(
            started.elapsed() < CHILD_SHUTDOWN_GRACE,
            "SIGTERM must end the child without waiting out the SIGKILL grace, \
             took {started:?}"
        );
        assert!(
            monitor.is_finished(),
            "the monitor must have observed (and reaped) the child"
        );
    }

    /// Liveness probe for a pid we do NOT own (cannot wait() it): signal 0
    /// succeeds while the pid exists — INCLUDING as an unreaped zombie (what
    /// a reparented grandchild becomes under a slow init). On Linux a /proc
    /// state of `Z` is therefore read as dead; elsewhere the signal probe
    /// alone is used.
    fn probe_alive(pid: u32) -> bool {
        if kill(Pid::from_raw(pid as i32), None).is_err() {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            // /proc/<pid>/stat is "pid (comm) state ..." and comm may contain
            // spaces and parens, so parse from after the LAST ')'.
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                && let Some(close) = stat.rfind(')')
                && let Some(state) = stat[close + 1..].trim().chars().next()
            {
                return state != 'Z';
            }
        }
        true
    }

    /// R3-1 regression, the `npm run dev` -> vite shape: teardown used to
    /// signal the direct child pid only, so the grandchild survived every
    /// worker exit. The child is a shell that backgrounds `sleep`, prints its
    /// pid, and waits; teardown must reach BOTH.
    #[tokio::test]
    async fn shutdown_child_command_kills_the_whole_group_including_a_grandchild() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();

        let mut child = spawn_command_child(
            &[
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from("sleep 30 & echo $!; wait"),
            ],
            port,
        )
        .expect("spawn shell child");
        let pid = child.id();
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut monitor = spawn_wait_monitor(child);

        // Read the grandchild's pid from the pipe, bounded against hangs.
        use tokio::io::AsyncBufReadExt;
        let grandchild_pid: u32 = {
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            let line = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
                .await
                .expect("the grandchild pid line must arrive within 5s")
                .expect("the child's stdout must not close before the pid line")
                .expect("the pid line must be present");
            line.trim()
                .parse()
                .expect("the grandchild pid must be numeric")
        };
        assert!(
            probe_alive(grandchild_pid),
            "the grandchild (pid {grandchild_pid}) must be running before teardown"
        );

        shutdown_child_command(pid, &mut monitor).await;

        // The group teardown reaches the grandchild even though the leader
        // dies first: a process group survives its leader while members
        // remain.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while probe_alive(grandchild_pid) && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            !probe_alive(grandchild_pid),
            "the group teardown must kill the grandchild (pid {grandchild_pid}), \
             not just the direct child"
        );
    }
}

/// Platform-neutral shutdown tests (the placeholder path is reachable on
/// every target: static/proxy workers and non-run foreground on Windows take
/// the same call).
#[cfg(test)]
mod command_shutdown_tests {
    use super::*;

    /// Round-1 blocker regression: every non-Run flow calls shutdown with
    /// pid=None and the placeholder in the monitor slot — an unconditional
    /// await there hung every static/proxy teardown at exit. The timeout
    /// bound turns a regression into a failing test instead of a hung suite.
    #[tokio::test]
    async fn pidless_placeholder_shutdown_completes_immediately() {
        const BOUND: std::time::Duration = std::time::Duration::from_secs(5);
        let mut monitor = command_monitor_placeholder();
        assert!(!monitor.is_finished(), "the placeholder starts pending");

        let started = std::time::Instant::now();
        tokio::time::timeout(BOUND, shutdown_child_command(None, &mut monitor))
            .await
            .expect("pid-less shutdown must complete, not hang on the placeholder");
        assert!(
            started.elapsed() < BOUND,
            "the pid-less path is a bounded no-op, took {started:?}"
        );
        assert!(
            monitor.is_finished(),
            "the placeholder task must be gone after shutdown"
        );
    }

    /// Same boundedness for an ALREADY-FINISHED monitor with a pid: complete
    /// without panicking on the dead pid (4_000_000 is outside any real pid
    /// namespace, so any signal fails harmlessly).
    #[tokio::test]
    async fn finished_monitor_shutdown_completes_immediately() {
        const BOUND: std::time::Duration = std::time::Duration::from_secs(5);
        let mut monitor = tokio::spawn(async {});
        // Let the trivial task finish so is_finished is the short-circuit
        // taken (the abort path is also fine — this pins the guard).
        for _ in 0..100 {
            if monitor.is_finished() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }

        let started = std::time::Instant::now();
        tokio::time::timeout(BOUND, shutdown_child_command(Some(4_000_000), &mut monitor))
            .await
            .expect("finished-monitor shutdown must complete");
        assert!(started.elapsed() < BOUND);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn process_exists_for_self() {
        assert!(process_exists(std::process::id()));
    }

    #[cfg(unix)]
    #[test]
    fn process_exists_false_for_dead_pid() {
        assert!(!process_exists(4_000_000));
    }

    /// The cmdline reader finds the current executable's name in our own
    /// process's command line.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn cmdline_contains_finds_self_process() {
        let exe = std::env::current_exe().expect("current_exe");
        let needle = exe
            .file_name()
            .and_then(|n| n.to_str())
            .expect("exe file name");
        // The exec path is the first argv entry, so the name always appears.
        assert!(cmdline_contains(std::process::id(), needle));
    }

    /// PID-reuse guard: [`terminate_orphan`]/[`terminate_foreground`] gate on
    /// cmdline identity immediately before signalling; a live foreign process
    /// (cmdline matches neither needle) must be left running. On
    /// non-needle-aware platforms `pid_matches` degrades to a liveness probe
    /// and the gate intentionally passes — the documented best-effort fallback.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn terminate_helpers_refuse_a_foreign_pid() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep child");
        let pid = child.id();

        terminate_orphan(pid);
        terminate_foreground(pid);

        // An ungated signal would kill `sleep` within milliseconds; the
        // settle window keeps a delayed delivery from reading as "gate held".
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "a foreign pid was signalled through the identity gate — \
             terminate_orphan/terminate_foreground must refuse non-matching pids"
        );

        // Gate held: clean up the child ourselves (kill + reap, no zombie).
        child.kill().expect("kill sleep child");
        child.wait().expect("reap sleep child");
    }

    /// CR-2 regression: the macOS argv parser must NOT match a needle that
    /// appears only in the environment region of a KERN_PROCARGS2 blob.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_argv_contains_ignores_environment() {
        // Build a synthetic blob: [argc=2][execpath\0][pad][argv[0]\0][argv[1]\0][envv\0...]
        let mut blob = Vec::new();
        blob.extend_from_slice(&2u32.to_le_bytes()); // argc = 2
        blob.extend_from_slice(b"/usr/local/bin/cloudflared\0"); // execpath
        blob.push(0); // alignment padding NUL
        blob.extend_from_slice(b"/usr/local/bin/cloudflared\0"); // argv[0]
        blob.extend_from_slice(b"tunnel\0"); // argv[1]
        // Environment: contains "run-worker" to prove the parser stops before it.
        blob.extend_from_slice(b"FOO=run-worker\0");
        blob.extend_from_slice(b"BAR=baz\0");

        // A needle present in argv matches.
        assert!(argv_contains(&blob, "tunnel"));
        // A needle present ONLY in envv does NOT match.
        assert!(!argv_contains(&blob, "run-worker"));
        assert!(!argv_contains(&blob, "FOO"));
    }

    /// macOS argv parser matches the needle across an argv entry (substring).
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_argv_contains_substring_in_argv() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes()); // argc = 1
        blob.extend_from_slice(b"/ft\0"); // execpath
        blob.extend_from_slice(b"ft run-worker --foreground\0"); // argv[0]
        assert!(argv_contains(&blob, "run-worker"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    //! Exercises the Windows FFI (TC-3): OpenProcess/WaitForSingleObject-based
    //! liveness, the image-name identity check, and the Job Object
    //! KILL_ON_JOB_CLOSE contract. These run on the windows-latest CI matrix.

    use super::*;

    #[test]
    fn process_exists_for_self() {
        assert!(process_exists(std::process::id()));
    }

    #[test]
    fn process_exists_false_for_dead_pid() {
        assert!(!process_exists(4_000_000));
    }

    /// The unknown-needle arm's refusal (WIN-5) is the stable claim we can
    /// make without assuming the binary name.
    #[test]
    fn pid_matches_unknown_needle_refuses() {
        // Unknown needles must NOT degrade to a plain liveness probe.
        assert!(!pid_matches(std::process::id(), "totally-bogus-needle"));
    }

    /// KILL_ON_JOB_CLOSE contract (TC-3): setup succeeds and the guard drops
    /// cleanly. The whole-tree kill cannot be proven in-process (it would kill
    /// this test); the null-handle-deref failure mode is covered because
    /// create_kill_on_close_job returns Some only for a valid handle.
    #[test]
    fn create_kill_on_close_job_succeeds_and_drops() {
        let guard = create_kill_on_close_job();
        assert!(guard.is_some(), "kill-on-close job creation failed");
        drop(guard); // must not panic / double-close
    }
}
