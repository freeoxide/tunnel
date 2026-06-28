//! Process introspection and signaling helpers.

use nix::sys::signal::{Signal, kill};
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
        cmdline_contains(pid, needle)
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

/// Gracefully tear down a process group: `SIGTERM`, poll for up to the grace
/// window for it to exit, then `SIGKILL` to guarantee cleanup. Both signals
/// target the whole group (negative pid) and are best-effort — members that are
/// already gone return `ESRCH`, which we ignore.
///
/// Async: the grace window is spent in `tokio::time::sleep` (with a liveness
/// poll so we SIGKILL as soon as the group is gone), never blocking the
/// executor. The earlier `std::thread::sleep` parked a tokio worker thread for
/// the full 1.5s on every `ft kill` / start-failure teardown.
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

/// Read `/proc/<pid>/cmdline` and report whether any argument contains `needle`.
#[cfg(target_os = "linux")]
fn cmdline_contains(pid: u32, needle: &str) -> bool {
    let path = Path::new("/proc").join(pid.to_string()).join("cmdline");
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    bytes.split(|b| *b == 0).any(|arg| {
        std::str::from_utf8(arg)
            .map(|s| s.contains(needle))
            .unwrap_or(false)
    })
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn cmdline_contains(_pid: u32, _needle: &str) -> bool {
    false
}
