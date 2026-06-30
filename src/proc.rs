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
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        QueryFullProcessImageNameW, TerminateProcess,
    };

    /// Rights we need on a target process: enough to query its image name /
    /// exit code AND to terminate it.
    const ACCESS: u32 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE;

    /// A process exit code meaning "still running" (Win32 `STILL_ACTIVE`).
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
        unsafe {
            let Some(h) = open(pid) else {
                return false;
            };
            let mut code: u32 = 0;
            let ok = GetExitCodeProcess(h, &mut code);
            let _ = CloseHandle(h);
            ok != 0 && code == STILL_ACTIVE
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
            _ => return process_exists(pid),
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

/// Read another process's command line on macOS via `sysctl(KERN_PROCARGS2)`
/// and report whether the blob contains `needle`.
///
/// `KERN_PROCARGS2` returns `[argc: u32][exec path\0][padding][argv\0...]
/// [envv\0...]`. Precise argv stepping past the variable padding is fiddly and
/// error-prone, so we substring-search the whole blob after the argc word. For
/// our needles (`run-worker`, `cloudflared`) a collision with a foreign
/// process's *environment* would require a contrived match and is negligible —
/// and this is strictly stronger than the prior signal-0-only fallback, which
/// ignored the needle entirely. Works for same-uid processes without root,
/// which is all we ever probe (our workers/cloudflared run as the same user).
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
    // Skip the leading argc word, then byte-substring-search the remainder.
    // Needles are ASCII, so a byte-window comparison is correct.
    let blob = if buf.len() > 4 { &buf[4..] } else { &buf[..] };
    blob.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Generic-Unix fallback with no portable cmdline reader (e.g. FreeBSD). Unused
/// on Linux/macOS/Windows; kept so the module links on those targets.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
#[allow(dead_code)]
fn cmdline_contains(_pid: u32, _needle: &str) -> bool {
    false
}

#[cfg(test)]
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
}
