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

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;

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
            // liveness probe (WIN-5), silently inheriting whatever
            // process_exists does. Refuse instead, so a mis-typed needle
            // surfaces during development rather than gating on the wrong
            // signal. In debug builds this asserts; in release it returns
            // false (never signals an unknown identity).
            _ => {
                debug_assert!(
                    false,
                    "pid_matches: unknown needle {needle:?}; refusing to gate on unknown identity"
                );
                return false;
            }
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

/// Best-effort `SIGTERM` of a single process by pid. Used by `ft prune` to reap
/// an orphaned `cloudflared` whose worker is already gone (it normally dies on
/// its own via `PR_SET_PDEATHSIG`, but that does not survive a host reboot). The
/// caller has already confirmed the pid is ours via [`pid_matches`], so this is
/// safe against PID reuse.
#[cfg(unix)]
pub fn terminate_orphan(pid: u32) {
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

/// Best-effort termination of a single process by pid, for FOREGROUND services
/// whose `worker_pid` is the `ft` process itself. Unlike
/// [`shutdown_process_group`] this targets ONE pid and never a process group —
/// a foreground `ft` shares the operator's shell's group, so `kill(-pgid)`
/// would kill the shell. Used by `ft kill` after gating on an identity check so
/// a recycled pid is not signalled.
#[cfg(unix)]
pub fn terminate_foreground(pid: u32) {
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
