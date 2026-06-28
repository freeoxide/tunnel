//! Process introspection and signaling helpers.

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::path::Path;

/// True if process `pid` exists and its command line contains `needle`.
///
/// On Linux this reads `/proc/<pid>/cmdline`, which defeats PID reuse: a dead
/// worker's PID recycled by an unrelated process will not contain `needle`, so
/// we will not mistake it for ours (and will not signal it). On other platforms
/// it falls back to a signal-0 liveness probe and `needle` is ignored.
pub fn pid_matches(pid: u32, needle: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        return cmdline_contains(pid, needle);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = needle;
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }
}

/// True if one of *our* workers is alive at `pid` (cmdline contains
/// `run-worker`).
pub fn pid_alive(pid: u32) -> bool {
    pid_matches(pid, "run-worker")
}

/// Gracefully tear down a process group: `SIGTERM`, give it a short grace
/// window to exit, then `SIGKILL` to guarantee cleanup. Both signals target the
/// whole group (negative pid) and are best-effort — members that are already
/// gone return `ESRCH`, which we ignore.
pub fn shutdown_process_group(pgid: u32) {
    let raw = -(pgid as i32);
    let _ = kill(Pid::from_raw(raw), Signal::SIGTERM);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let _ = kill(Pid::from_raw(raw), Signal::SIGKILL);
}

/// Read `/proc/<pid>/cmdline` and report whether any argument contains `needle`.
#[cfg(target_os = "linux")]
fn cmdline_contains(pid: u32, needle: &str) -> bool {
    let path = Path::new("/proc").join(pid.to_string()).join("cmdline");
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    bytes
        .split(|b| *b == 0)
        .any(|arg| std::str::from_utf8(arg).map(|s| s.contains(needle)).unwrap_or(false))
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn cmdline_contains(_pid: u32, _needle: &str) -> bool {
    false
}
