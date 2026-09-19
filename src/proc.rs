//! Process introspection and signaling helpers.
//!
//! Two kinds of probes:
//! - [`pid_matches`] / [`pid_alive`]: a *cmdline-aware* identity check. On Linux
//!   it reads `/proc/<pid>/cmdline`; on macOS it reads the process args via
//!   `sysctl(KERN_PROCARGS2)`. Both defeat PID reuse: a dead worker's pid
//!   recycled by an unrelated process will not contain the needle (`run-worker`
//!   / `cloudflared`), so it is never mistaken for ours and never signalled. On
//!   Windows the same idea is approximated by checking the process image name
//!   (`ft.exe` / `cloudflared.exe`) via `QueryFullProcessImageNameW`. On other
//!   Unix there is no portable cmdline reader, so it falls back to a signal-0
//!   liveness probe (the identity guarantee is best-effort there).
//! - [`process_exists`]: a plain liveness check with no needle, used for
//!   foreground services (whose `ft` cmdline lacks the `run-worker` token).
//!
//! Signalling: Unix uses `SIGTERM`→grace→`SIGKILL` on a process group
//! (`kill(-pgid)`). Windows terminates a single process via `TerminateProcess`
//! — the detached worker owns a Job Object (`KILL_ON_JOB_CLOSE`, see
//! `worker::run`), so terminating the worker cascades to its whole tree
//! (cloudflared), giving the same whole-tree teardown as the Unix group kill.
//! A spawned command child additionally leads its OWN process group (see
//! `own_process_group`), so the worker's exit paths can tear the whole command
//! subtree down with `killpg` without ever signalling the worker's group.

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;
use tokio::process::{Child, Command};

// --- run-service command children -------------------------------------------
//
// A `Run` service's local origin is a command `ft` itself spawns (the
// operator's dev server). The detached worker and the foreground flow share
// the spawn + teardown discipline below, mirroring how cloudflared itself is
// handled where it is safe to do so: Linux adds PR_SET_PDEATHSIG against a
// SIGKILL'd spawner, and Windows relies on the worker's KILL_ON_JOB_CLOSE Job
// Object (plus an explicit terminate on the foreground paths, which run no
// job). The one deliberate difference from cloudflared: the command child is
// moved into its OWN process group at spawn (`own_process_group`), so
// teardown can `killpg` the entire command subtree — the child plus every
// grandchild it forks (`npm run dev` -> vite) — on every exit path, without
// ever signalling the spawner's group (which in the detached-worker flow
// contains the worker itself and cloudflared, and in the foreground flow is
// the operator's shell's group; a group kill there would be suicide in the
// first case and would kill the shell in the second).

/// Spawn the user's command child with `PORT=port` exported, so well-behaved
/// dev servers pick their port up from the environment instead of a flag.
///
/// stdout/stderr are piped (the caller tees them into `worker.log`, which is
/// what `ft logs` reads), stdin is null. On Unix the child is made the leader
/// of its own process group (see [`own_process_group`]), which is what lets
/// [`shutdown_child_command`] take the whole command subtree down on every
/// spawner exit path — see the module-level discipline note above.
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

    // Process-group isolation (R3-1): without this the child inherits the
    // spawner's group — the worker's own group when detached, the operator's
    // SHELL's group in the foreground flow — and no safe group signal could
    // ever reach the grandchildren. Made fatal rather than best-effort: if
    // the child is not a group leader, killpg teardown would target a group
    // that is not exclusively the command subtree's (or no group at all), so
    // failing the spawn loudly is the only honest behavior.
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(own_process_group);
    }

    // Best-effort: on Linux, SIGKILL the child if its parent (the worker or
    // foreground ft) dies — even via SIGKILL or OOM — so the command can never
    // outlive the process that owns its tunnel. Shares the named pre-exec hook
    // with `cloudflared::spawn` (single source of truth for the fork→prctl
    // race handling; the getppid re-check closes the window — see
    // [`parent_death_signal`] for the full discussion).
    #[cfg(target_os = "linux")]
    unsafe {
        cmd.pre_exec(parent_death_signal);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn command {bin:?}"))?;
    Ok(child)
}

/// Unix-only pre-exec hook: make the calling (pre-exec) child a process-group
/// leader, so its pgid equals its pid and `killpg(child_pid)` later reaches
/// exactly the command subtree — the child plus every grandchild it forks.
/// The pre-exec window is the only safe place to do this: the choice belongs
/// to ft (the child must not be left to inherit or change its group before we
/// pin it), and the child has not yet exec'd into arbitrary operator code.
#[cfg(unix)]
fn own_process_group() -> Result<(), std::io::Error> {
    // setpgid(0, 0) only moves this not-yet-exec'd child into a fresh process
    // group of its own; nix wraps the raw syscall safely, so no unsafe block
    // is needed here.
    nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0))
        .map_err(|e| std::io::Error::other(format!("setpgid failed: {e}")))
}

/// Linux-only pre-exec hook: request SIGKILL on parent death and refuse to
/// exec if the parent is ALREADY gone (reparented to init). Kept as a named,
/// `pub(crate)` function so both pre-exec sites — the command child here and
/// `cloudflared::spawn` — share ONE implementation of the race handling
/// instead of staying manually in sync.
#[cfg(target_os = "linux")]
pub(crate) fn parent_death_signal() -> Result<(), std::io::Error> {
    // SAFETY: prctl only sets a kernel attribute on this (pre-exec) process;
    // getppid is a plain read. A failed prctl is surfaced — the whole point of
    // the hook is the death signal, and skipping it silently (as the inline
    // copy cloudflared::spawn once carried did) is exactly what it must
    // prevent.
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
/// (and thereby reaps) it.
///
/// The keep-alive `select!` in the worker and foreground flows needs a
/// child-exit arm, while the teardown paths need to signal the child by pid —
/// impossible while tokio's owned `Child` is mutably borrowed by a `wait()`.
/// The monitor resolves the split: it owns the handle (exit observed, zombie
/// reaped), the spawner keeps the bare pid for signalling, and
/// [`shutdown_child_command`] coordinates the two.
pub(crate) fn spawn_wait_monitor(mut child: Child) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = child.wait().await;
    })
}

/// Grace before a SIGTERM'd command child is SIGKILL'd (Unix). Slightly longer
/// than cloudflared's: dev servers often flush state (build caches, sockets)
/// on TERM and are the thing the operator is iterating on.
#[cfg(unix)]
const CHILD_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// The never-completing monitor stand-in for flows that spawn no command
/// child (static/proxy workers, non-run foreground): the keep-alive `select!`
/// needs a monitor binding, and [`shutdown_child_command`] treats the
/// pid-less call as its bounded no-op (abort + await — a pending future never
/// resolves on its own). One shared constructor so the placeholder shape the
/// tests pin is the exact one production uses.
pub(crate) fn command_monitor_placeholder() -> tokio::task::JoinHandle<()> {
    tokio::spawn(std::future::pending())
}

/// Tear down the spawned command child — the counterpart of
/// [`spawn_wait_monitor`].
///
/// `pid == None` means NO command child was ever spawned: the monitor slot
/// holds the never-completing placeholder, so this must be a bounded no-op,
/// not just a polite one — awaiting the placeholder there would hang EVERY
/// non-Run worker and foreground teardown (the round-1 blocker). The
/// placeholder is aborted (which resolves it immediately) so no parked task
/// is left behind.
///
/// With a pid: a finished monitor means the child already exited and was
/// reaped — nothing to signal, nothing left to reap. Otherwise Unix signals
/// the child's WHOLE process group (SIGTERM, bounded wait, SIGKILL): the
/// child was made a group leader at spawn ([`own_process_group`]), so the
/// negative pid covers the entire command subtree — the direct child AND the
/// grandchildren it forked (`npm run dev` -> vite), which a direct-pid signal
/// never reached (R3-1). The pgid is pinned against reuse the same way the
/// Windows pid path is: the monitor's open `Child` handle means the child has
/// not been reaped, so a dead leader's group still exists (groups survive
/// their leader while members remain) and cannot have been recycled.
/// Windows terminates by pid — sound without an identity needle because the
/// monitor's open `Child` handle pins the pid against reuse until this call
/// aborts it — and the worker's Job Object additionally guarantees whole-tree
/// teardown when the flow exits.
pub(crate) async fn shutdown_child_command(
    pid: Option<u32>,
    monitor: &mut tokio::task::JoinHandle<()>,
) {
    // No child, no signal path: abort the placeholder (a pending future never
    // resolves on its own) and reap the task handle so teardown completes.
    let Some(pid) = pid else {
        monitor.abort();
        let _ = monitor.await;
        return;
    };
    // The monitor already observed the child's exit: nothing to signal,
    // nothing left to reap.
    if monitor.is_finished() {
        return;
    }
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        // Negative pid = whole process group. Safe to include the direct
        // child and every descendant: the group was created for this command
        // subtree alone at spawn time (own_process_group) and is guarded
        // against pid reuse by the not-yet-reaped monitor's open handle (the
        // is_finished guard above). Members already gone return ESRCH, which
        // is ignored.
        let group = Pid::from_raw(-(pid as i32));
        let _ = kill(group, Signal::SIGTERM);
        if tokio::time::timeout(CHILD_SHUTDOWN_GRACE, &mut *monitor)
            .await
            .is_err()
        {
            // Still running past the grace: SIGKILL is un-ignoreable, and the
            // monitor is guaranteed still pending here (the timeout only
            // elapses when the monitor did NOT complete), so this await is
            // bounded and safe.
            let _ = kill(group, Signal::SIGKILL);
            let _ = (&mut *monitor).await;
        }
        // On the Ok arm the timeout's await already observed the child's
        // completion AND reaped it via the monitor's own wait() — the handle
        // is consumed and must NOT be polled again (tokio panics on a
        // JoinHandle polled after completion).
    }
    #[cfg(windows)]
    {
        windows_proc::terminate_child(pid);
        monitor.abort();
        let _ = monitor.await;
    }
    // No terminate primitive exists on an unsupported target; the monitor is
    // still reaped so the flow never leaves a dangling task behind.
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        monitor.abort();
        let _ = monitor.await;
    }
}

/// True if process `pid` exists and its command line contains `needle`.
///
/// On Linux this reads `/proc/<pid>/cmdline`; on macOS it reads the process
/// arguments via `sysctl(KERN_PROCARGS2)`; on Windows it checks the process
/// image-name suffix (`run-worker`/`--foreground` -> `ft.exe`, `cloudflared` ->
/// `cloudflared.exe`). All defeat PID reuse. On other Unix there is no portable
/// equivalent, so it falls back to a signal-0 liveness probe and the needle is
/// ignored (the identity guarantee is Linux/macOS/Windows only).
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

/// True if a process with `pid` is currently running (no identity check).
///
/// Used for foreground services, whose host is the `ft` process itself and
/// whose cmdline therefore lacks the `"run-worker"` token that [`pid_alive`]
/// looks for. A foreground service is never confused with a recycled pid for
/// signalling because `ft kill` signals it by the recorded pid directly (gated
/// on its own identity check).
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
    /// Kept only for documentation — we no longer use it to decide liveness,
    /// because a process that legitimately exits with code 259 would be
    /// misreported as alive forever (WIN-1). Liveness is decided by
    /// `WaitForSingleObject` instead.
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
        // Liveness via a non-blocking wait (WIN-1). `GetExitCodeProcess`
        // returning 259 (STILL_ACTIVE) is a SENTINEL, not a guarantee: a
        // process that really exits with code 259 keeps that code forever and
        // would read as alive indefinitely. `WaitForSingleObject(h, 0)` returns
        // WAIT_TIMEOUT while the process is running and WAIT_OBJECT_0 once it
        // has exited, with no 259 ambiguity.
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
        // Map our cmdline "needle" concept to a Windows image-name suffix.
        let want = match needle {
            "run-worker" | "--foreground" => "ft.exe",
            "cloudflared" => "cloudflared.exe",
            // An unrecognized needle would previously degrade to a plain
            // liveness probe (WIN-5). Refuse instead (return false) so a
            // mis-typed needle never gates on the wrong identity. NOTE: no
            // debug_assert!(false) here — it would panic under `cargo test`
            // (debug_assertions are on in the dev profile), and the unit test
            // in `windows_tests` exercises exactly this refusal path.
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

    /// Terminate a spawned command child by pid, WITHOUT an identity needle.
    ///
    /// Sound despite the usual PID-reuse concern because the caller only
    /// reaches here while the command-child monitor still holds the tokio
    /// `Child` handle — an open handle pins the pid against kernel reuse on
    /// Windows — and `shutdown_child_command` checked `is_finished` first.
    pub fn terminate_child(pid: u32) {
        let _ = terminate(pid);
    }

    /// Terminate a foreground `ft` process by pid (gated on identity; never the
    /// group, which would kill the operator's shell).
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
    /// and return a guard. Hold the guard for the worker's lifetime: when the
    /// worker exits for any reason (graceful, killed, OOM, crash) the OS closes
    /// the handle and kills the whole job (cloudflared) — the Windows
    /// equivalent of Linux's `PR_SET_PDEATHSIG`. Returns `None` (after logging)
    /// if setup fails, in which case the worker still runs but a hard-killed
    /// worker will not auto-reap cloudflared.
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
// `shutdown_child_command` in this module, which reaches it through the
// `windows_proc` module path. Re-exporting it anyway made the import unused
// under the Windows target (a bin crate warns on crate-internal `pub use`
// nothing else references) — invisible to every Linux gate.
#[cfg(windows)]
pub use windows_proc::{
    create_kill_on_close_job, pid_alive, pid_matches, process_exists, shutdown_process_group,
    terminate_foreground, terminate_orphan,
};

/// Gracefully tear down a process group: `SIGTERM`, poll for up to the grace
/// window for it to exit, then `SIGKILL` to guarantee cleanup. Both signals
/// target the whole group (negative pid) and are best-effort — members that are
/// already gone return `ESRCH`, which we ignore.
///
/// Async: the grace window is spent in `tokio::time::sleep` (with a liveness
/// poll so we SIGKILL as soon as the group is gone), never blocking the
/// executor.
#[cfg(unix)]
pub async fn shutdown_process_group(pgid: u32) {
    // pgid == 0 means "no group recorded": kill(-0) is kill(0), which signals
    // the CALLER's own process group (self-kill). Treat it as a no-op.
    if pgid == 0 {
        return;
    }
    // Identity gate (CR-1): mirror the Windows shutdown_process_group, which
    // only terminates after `pid_matches(pgid, "run-worker")` confirms the
    // process group leader is still one of our workers. The pgid is the worker
    // pid; if the worker died and the kernel recycled that pid into an
    // unrelated process group, kill(-pgid) would signal the wrong group. The
    // group leader's identity is a strong proxy for "this is still our worker
    // tree": a recycled leader will not have `run-worker` in its cmdline, so we
    // refuse to signal it.
    if !pid_matches(pgid, "run-worker") {
        tracing::debug!(
            "shutdown_process_group: pgid {} no longer matches run-worker; refusing to signal (recycled-pid guard)",
            pgid
        );
        return;
    }
    let raw = -(pgid as i32);
    let _ = kill(Pid::from_raw(raw), Signal::SIGTERM);
    // Poll group liveness (kill -pgid with signal 0 returns ESRCH once no
    // process remains in the group) so we usually return well before the grace
    // window elapses, and never block the runtime while waiting.
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

/// Best-effort `SIGTERM` of a single process by pid. Used by `ft prune` and
/// `ft sanitize` to reap an orphaned `cloudflared` whose worker is already gone
/// (it normally dies on its own via `PR_SET_PDEATHSIG`, but that does not
/// survive a host reboot). The `cloudflared` identity gate lives HERE,
/// immediately before the signal: the callers check [`pid_matches`] at collect
/// time and signal later — in prune/sanitize an entire locked registry save
/// sits in between — so a pid recycled inside that window must be re-verified
/// rather than signalled on the caller's stale say-so. Mirrors the Windows
/// `terminate_orphan` gate.
#[cfg(unix)]
pub fn terminate_orphan(pid: u32) {
    if !pid_matches(pid, "cloudflared") {
        return;
    }
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

/// Best-effort termination of a single process by pid, for FOREGROUND services
/// whose `worker_pid` is the `ft` process itself. Unlike
/// [`shutdown_process_group`] this targets ONE pid and never a process group —
/// a foreground `ft` shares the operator's shell's group, so `kill(-pgid)`
/// would kill the shell. The `--foreground` identity gate lives HERE,
/// immediately before the signal (the caller in `ft kill` gates too, but its
/// check can go stale before this call runs — the same recycled-pid window
/// [`terminate_orphan`] closes); mirrors the Windows `terminate_foreground`.
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

/// Upper bound on the KERN_PROCARGS2 allocation. A blob this large is not one
/// of our own processes; capping avoids a multi-MB allocation per probe if a
/// probed process has a pathologically huge argv/env block (EH-2).
#[cfg(target_os = "macos")]
const MAX_PROCARGS_BYTES: usize = 1024 * 1024;

/// Read another process's command line on macOS via `sysctl(KERN_PROCARGS2)`
/// and report whether any *argv* entry contains `needle`.
///
/// `KERN_PROCARGS2` layout is `[argc:u32][execpath\0][NUL padding][argv\0...]
/// [envv\0...]`. We parse it into proper argv boundaries and search ONLY the
/// argv region — never the environment — so the needle cannot collide with a
/// foreign process's env vars (CR-2). Works for same-uid processes without
/// root, which is all we ever probe (our workers/cloudflared run as the same
/// user).
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
    // Cap the allocation (EH-2): a blob larger than 1 MiB cannot be one of our
    // own worker/cloudflared processes, so refuse rather than over-allocate.
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
/// `needle`. Extracted as a pure helper so it can be unit-tested without a
/// real process.
///
/// Layout: `[argc:u32 LE][execpath\0][NUL padding][argv[0]\0 ... argv[argc-1]\0]
/// [envv\0...]`. `argc` counts argv entries INCLUDING argv[0] (the exec path).
/// We: read argc, skip the execpath string, skip trailing NUL padding, then
/// walk exactly `argc` NUL-terminated entries. Anything past that is envv and
/// is never searched.
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

    // Skip alignment padding: a run of NUL bytes between execpath and argv[0].
    // The real argv entries are non-empty (at least the exec path), so any NUL
    // here is padding.
    while pos < blob.len() && blob[pos] == 0 {
        pos += 1;
    }

    // Walk exactly `argc` NUL-terminated argv entries. Searching argv only (not
    // envv) is the whole point — see CR-2.
    let needle_bytes = needle.as_bytes();
    for _ in 0..argc {
        if pos >= blob.len() {
            // Truncated blob: fewer entries than argc promised. We have already
            // searched every argv entry that was present, so it is safe to stop.
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

/// Generic-Unix fallback with no portable cmdline reader (e.g. FreeBSD). Unused
/// on Linux/macOS/Windows; kept so the module links on those targets.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
#[allow(dead_code)]
fn cmdline_contains(_pid: u32, _needle: &str) -> bool {
    false
}

#[cfg(all(test, unix))]
mod command_child_tests {
    use super::*;
    use std::ffi::OsString;

    /// The contract that lets `ft run` skip a `--port` flag on the child: the
    /// spawned command must find its port in `PORT`. Proven end-to-end through
    /// a real child (a shell that echoes `$PORT`), since env inheritance has
    /// no pure seam.
    #[tokio::test]
    async fn command_child_receives_port_in_its_environment() {
        // Any port value works — the child only reads the env var; the
        // listener merely produces a realistic, in-use-looking port number.
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

    /// The full teardown path against a REAL child: SIGTERM lands, the
    /// monitor observes the exit and reaps it, and shutdown returns well
    /// inside the SIGKILL grace (no escalation was needed). This is the
    /// companion to the placeholder test below — one proves the no-child
    /// path is bounded, this proves the with-child path actually kills.
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

    /// Liveness probe for a pid we do NOT own (a grandchild cannot be
    /// wait()ed by this process): signal 0 succeeds while the pid exists —
    /// INCLUDING as an unreaped zombie, which is what a reparented
    /// grandchild becomes when this environment's init is slow to reap. A
    /// /proc state of `Z` is therefore read as dead on Linux; elsewhere the
    /// signal probe alone is used (launchd/init reap orphans promptly).
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

    /// R3-1 regression against a REAL child that forks a grandchild — the
    /// `npm run dev` -> vite shape: the worker's exit paths funnel into
    /// `shutdown_child_command`, which used to signal the DIRECT child pid
    /// only, so the grandchild (the process actually holding the port)
    /// survived every worker exit. The child here is a shell that starts
    /// `sleep` in the background, prints its pid, and stays alive in `wait`;
    /// teardown must reach BOTH.
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

        // Read the grandchild's pid from the pipe, bounded so a broken pipe
        // can never hang the suite.
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

        // The group teardown must reach the grandchild too — and it does so
        // even though the shell (the group leader) dies first, because a
        // process group survives its leader while members remain.
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
/// every target the crate ships: static/proxy workers and non-run foreground
/// on Windows take the same call).
#[cfg(test)]
mod command_shutdown_tests {
    use super::*;

    /// Round-1 blocker regression: every non-Run flow calls shutdown with
    /// pid=None and [`command_monitor_placeholder`] in the monitor slot. That
    /// call MUST complete — the placeholder never resolves on its own, so an
    /// unconditional await there hung every static/proxy worker and
    /// foreground teardown at exit (registry cleanup included). The timeout
    /// bound turns any regression into a failing test instead of a hung
    /// suite, and the finished-check proves the placeholder was actually
    /// reaped, not left parked.
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

    /// The same boundedness contract for an ALREADY-FINISHED monitor with a
    /// pid: shutdown must complete (and must not panic on a dead/nonexistent
    /// pid — 4_000_000 is far outside any real pid namespace, so any signal
    /// sent there fails harmlessly). The is_finished guard makes this the
    /// pure short-circuit; the timeout bound keeps it honest.
    #[tokio::test]
    async fn finished_monitor_shutdown_completes_immediately() {
        const BOUND: std::time::Duration = std::time::Duration::from_secs(5);
        let mut monitor = tokio::spawn(async {});
        // Give the trivial task a chance to finish so is_finished is the
        // short-circuit taken (an unfinished task would take the abort path,
        // which is also fine — this test pins the guard, not the scheduler).
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

    /// On Linux/macOS the cmdline reader must find the current executable's name
    /// in our own process's command line. (Runs only on the matching CI matrix.)
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn cmdline_contains_finds_self_process() {
        let exe = std::env::current_exe().expect("current_exe");
        let needle = exe
            .file_name()
            .and_then(|n| n.to_str())
            .expect("exe file name");
        // The exec path is the first entry in the procargs blob, so the binary
        // name always appears.
        assert!(cmdline_contains(std::process::id(), needle));
    }

    /// PID-reuse guard: [`terminate_orphan`] and [`terminate_foreground`] gate
    /// on cmdline identity INTERNALLY, immediately before signalling. The
    /// callers (kill/prune/sanitize) check identity at collect time and signal
    /// later — in prune/sanitize an entire locked registry save sits in
    /// between — so a pid recycled in that window must be refused here, never
    /// signalled on the caller's stale say-so. A live `sleep` child's cmdline
    /// contains neither needle, so both calls must leave it running.
    /// (Needle-aware platforms only: elsewhere `pid_matches` degrades to a
    /// signal-0 liveness probe and the gate intentionally passes for a live
    /// foreign process — the documented best-effort fallback.)
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

        // A regression (an ungated signal) would deliver SIGTERM to `sleep`,
        // which dies within milliseconds; the short settle window keeps a
        // delayed delivery from reading as "gate held".
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

    /// The current process is the test binary; its image name ends in whatever
    /// cargo built (e.g. `.exe`), so the unknown-needle arm's refusal is the
    /// stable, assertion-free claim we can make without assuming the binary
    /// name. We assert that a known needle is at least callable without panic
    /// and that an unknown needle refuses (WIN-5).
    #[test]
    fn pid_matches_unknown_needle_refuses() {
        // Unknown needles must NOT degrade to a plain liveness probe; they
        // return false (refuse to gate on an unknown identity).
        assert!(!pid_matches(std::process::id(), "totally-bogus-needle"));
    }

    /// KILL_ON_JOB_CLOSE contract (TC-3): creating a kill-on-close job and
    /// dropping its guard must not crash and must close the underlying handle.
    /// We cannot easily prove the whole-tree kill in-process (it would kill
    /// this test process), so we verify setup succeeds and the guard drops
    /// cleanly — the untested failure mode (null-handle deref in Drop) is
    /// covered because create_kill_on_close_job returns Some only when the
    /// handle is valid.
    #[test]
    fn create_kill_on_close_job_succeeds_and_drops() {
        let guard = create_kill_on_close_job();
        assert!(guard.is_some(), "kill-on-close job creation failed");
        drop(guard); // must not panic / double-close
    }
}
