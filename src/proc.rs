//! Process introspection and signaling helpers.

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::io;
use std::path::Path;

/// True if a process with the given PID is one of *our* workers and is alive.
///
/// On Linux we require `/proc/<pid>/cmdline` to contain `run-worker`, which
/// defeats the PID-reuse false positive where the kernel recycles a dead
/// worker's PID for an unrelated process. On other platforms we fall back to a
/// signal-0 probe.
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        return worker_cmdline_matches(pid);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }
}

/// Send `SIGTERM` to an entire process group.
///
/// `pgid` is expected to be the worker's PID, since the worker calls
/// `setsid()` on spawn (so its process-group id equals its pid). A negative
/// pid targets the whole group, which includes the `cloudflared` child.
pub fn kill_process_group(pgid: u32) -> io::Result<()> {
    kill(
        Pid::from_raw(-(pgid as i32)),
        Signal::SIGTERM,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

/// Best-effort: returns true if `/proc/<pid>/cmdline` looks like our worker.
#[cfg(target_os = "linux")]
fn worker_cmdline_matches(pid: u32) -> bool {
    let path = Path::new("/proc").join(pid.to_string()).join("cmdline");
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    bytes
        .split(|b| *b == 0)
        .filter_map(|s| std::str::from_utf8(s).ok())
        .any(|arg| arg.contains("run-worker"))
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn worker_cmdline_matches(_pid: u32) -> bool {
    false
}
