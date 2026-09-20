//! Process introspection and signaling helpers.
//!
//! [`pid_matches`]/[`pid_alive`]: cmdline-aware identity that defeats PID
//! reuse (Linux `/proc/<pid>/cmdline`; macOS `sysctl(KERN_PROCARGS2)`; Windows
//! image name; other Unix: signal-0 liveness, identity best-effort).
//! [`process_exists`]: needle-less liveness for foreground services, whose
//! cmdline lacks the `run-worker` token. Signalling: Unix SIGTERM→grace→
//! SIGKILL on the process group; Windows `TerminateProcess` — the worker's
//! KILL_ON_JOB_CLOSE Job Object cascades to the whole tree.

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;
use tokio::process::{Child, Command};

// --- run-service command children -------------------------------------------
// The command child leads its OWN group — killpg reaches the subtree only.

/// Spawn the command child with `PORT=port`; on Unix it leads its own group
/// ([`own_process_group`]) so [`shutdown_child_command`] takes the subtree down.
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

    // Without a fresh group no safe group signal could reach the
    // grandchildren — killpg would target a group the subtree does not own.
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(own_process_group);
    }

    // On Linux, SIGKILL the child if its spawner dies (even via SIGKILL/OOM);
    // shared pre-exec hook with `cloudflared::spawn` ([`parent_death_signal`]).
    #[cfg(target_os = "linux")]
    unsafe {
        cmd.pre_exec(parent_death_signal);
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn command {bin:?}"))?;
    Ok(child)
}

/// Make the (pre-exec) child a group leader so `killpg(child_pid)` reaches
/// exactly the subtree; pre-exec is the only safe window before operator code.
#[cfg(unix)]
fn own_process_group() -> Result<(), std::io::Error> {
    nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0))
        .map_err(|e| std::io::Error::other(format!("setpgid failed: {e}")))
}

/// Request SIGKILL on parent death; refuse to exec if the parent is already
/// gone (getppid()==1). `pub(crate)`: both pre-exec sites share this handler.
#[cfg(target_os = "linux")]
pub(crate) fn parent_death_signal() -> Result<(), std::io::Error> {
    // SAFETY: prctl sets a kernel attribute on this pre-exec process; a
    // failed prctl is surfaced — exec'ing without the death signal is the
    // exact failure this hook must prevent.
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

/// Await (reap) the child in a background task: the `select!` needs an exit
/// arm while teardown signals by pid — a `wait()` would borrow the `Child`.
pub(crate) fn spawn_wait_monitor(mut child: Child) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = child.wait().await;
    })
}

/// Grace before a SIGTERM'd command child is SIGKILL'd (Unix). Slightly longer
/// than cloudflared's: dev servers often flush state on TERM.
#[cfg(unix)]
const CHILD_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Never-completing monitor stand-in for flows that spawn no command child;
/// the pid-less [`shutdown_child_command`] treats it as a bounded no-op.
pub(crate) fn command_monitor_placeholder() -> tokio::task::JoinHandle<()> {
    tokio::spawn(std::future::pending())
}

/// Tear down the spawned command child (counterpart of [`spawn_wait_monitor`]).
///
/// `pid == None`: bounded no-op — abort + await the placeholder; awaiting its
/// pending future would hang every non-Run teardown. A finished monitor means
/// the child already exited and was reaped. Unix signals the child's WHOLE
/// process group (it leads one; the monitor's open `Child` handle pins the
/// group against pid reuse). Windows terminates by pid — sound for the same
/// handle-pinning reason — and the Job Object reaps the rest of the tree.
pub(crate) async fn shutdown_child_command(
    pid: Option<u32>,
    monitor: &mut tokio::task::JoinHandle<()>,
) {
    let Some(pid) = pid else {
        monitor.abort();
        let _ = monitor.await;
        return;
    };
    if monitor.is_finished() {
        return;
    }
    #[cfg(unix)]
    {
        let group = Pid::from_raw(-(pid as i32));
        let _ = kill(group, Signal::SIGTERM);
        if tokio::time::timeout(CHILD_SHUTDOWN_GRACE, &mut *monitor)
            .await
            .is_err()
        {
            // SIGKILL is un-ignoreable; the timeout's elapse guarantees the
            // monitor is still pending, so this await is bounded.
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
    // No terminate primitive on an unsupported target; still reap the monitor.
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        monitor.abort();
        let _ = monitor.await;
    }
}

/// Pid exists AND its cmdline contains `needle` — defeats PID reuse (per-OS
/// mechanisms in the module docs; other Unix falls back to liveness only).
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

/// Plain liveness (no identity) — for foreground services, whose `ft` cmdline
/// lacks the `run-worker` token; callers gate identity themselves.
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

    /// Win32 `STILL_ACTIVE` — never used for liveness: a real exit with 259
    /// reads alive forever; liveness is `WaitForSingleObject`.
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
        let want = match needle {
            "run-worker" | "--foreground" => "ft.exe",
            "cloudflared" => "cloudflared.exe",
            // An unrecognized needle refuses rather than degrading to a
            // liveness probe — no debug_assert!, cargo test runs this path.
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

    /// Stop a detached worker: terminate the worker pid; its Job Object kills
    /// the whole tree. `pgid == 0` means "no worker recorded" — a no-op.
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

    /// Terminate a spawned command child by pid, no identity needle: sound
    /// only while the monitor's open `Child` handle pins the pid against reuse.
    pub fn terminate_child(pid: u32) {
        let _ = terminate(pid);
    }

    /// Terminate a foreground `ft` pid (identity-gated; never the group —
    /// it shares the operator's shell's).
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

    /// Create a Job Object with KILL_ON_JOB_CLOSE, assign THIS process, and
    /// return a guard: when the worker exits the OS closes the handle and
    /// kills the job — the Windows `PR_SET_PDEATHSIG`. `None` (after logging)
    /// if setup fails: the worker runs but a hard-killed one won't auto-reap.
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

// `terminate_child` stays private: its only caller is in this module, and an
// unreferenced `pub use` warns on Windows (invisible to Linux gates).
#[cfg(windows)]
pub use windows_proc::{
    create_kill_on_close_job, pid_alive, pid_matches, process_exists, shutdown_process_group,
    terminate_foreground, terminate_orphan,
};

/// `SIGTERM`, poll the grace, `SIGKILL` — whole group (negative pid),
/// best-effort; the grace waits in `tokio::time::sleep`, never blocking.
#[cfg(unix)]
pub async fn shutdown_process_group(pgid: u32) {
    // pgid == 0 means "no group recorded": kill(-0) is kill(0), which
    // signals the CALLER's own group (self-kill). No-op instead.
    if pgid == 0 {
        return;
    }
    // Recycled-pid guard: the pgid is the worker pid; a recycled leader lacks
    // `run-worker` in its cmdline, so refuse to signal the wrong group.
    if !pid_matches(pgid, "run-worker") {
        tracing::debug!(
            "shutdown_process_group: pgid {} no longer matches run-worker; refusing to signal (recycled-pid guard)",
            pgid
        );
        return;
    }
    let raw = -(pgid as i32);
    let _ = kill(Pid::from_raw(raw), Signal::SIGTERM);
    // signal-0 kill returns ESRCH once the group is empty.
    let deadline = std::time::Duration::from_millis(1500);
    let step = std::time::Duration::from_millis(50);
    let mut waited = std::time::Duration::ZERO;
    while waited < deadline {
        if kill(Pid::from_raw(raw), None).is_err() {
            return;
        }
        tokio::time::sleep(step).await;
        waited += step;
    }
    let _ = kill(Pid::from_raw(raw), Signal::SIGKILL);
}

/// Best-effort `SIGTERM` of an orphaned cloudflared (its worker is gone —
/// `PR_SET_PDEATHSIG` does not survive a host reboot). The identity gate
/// lives HERE, right before the signal: callers decide and signal later (in
/// prune/sanitize a locked registry save sits between), so a pid recycled in
/// that window must be re-verified, never signalled on stale say-so.
#[cfg(unix)]
pub fn terminate_orphan(pid: u32) {
    if !pid_matches(pid, "cloudflared") {
        return;
    }
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

/// SIGTERM one foreground `ft` pid — never the group (the operator's shell
/// is in it); identity-gated for [`terminate_orphan`]'s reuse window.
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

/// Cap on the KERN_PROCARGS2 allocation: over 1 MiB cannot be one of ours,
/// and the cap bounds a pathological argv/env block.
#[cfg(target_os = "macos")]
const MAX_PROCARGS_BYTES: usize = 1024 * 1024;

/// Read another process's cmdline on macOS via `sysctl(KERN_PROCARGS2)`:
/// layout `[argc:u32][execpath\0][pad][argv...][envv...]` — search ONLY the
/// argv region, never envv, so the needle cannot match a foreign env var.
/// Works for same-uid processes without root.
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
    // Cap the allocation: over 1 MiB cannot be one of ours — refuse.
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

/// Parse a `KERN_PROCARGS2` blob: read argc, skip execpath + padding, walk
/// exactly `argc` NUL-terminated entries — past that is envv, never searched.
#[cfg(target_os = "macos")]
fn argv_contains(blob: &[u8], needle: &str) -> bool {
    if blob.len() < 4 {
        return false;
    }
    let argc = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if argc == 0 {
        return false;
    }
    let mut pos = 4;

    let Some(exec_end) = blob[pos..].iter().position(|&b| b == 0) else {
        return false;
    };
    pos += exec_end + 1;

    // Skip alignment padding: real argv entries are non-empty (at least the
    // exec path), so any NUL here is padding.
    while pos < blob.len() && blob[pos] == 0 {
        pos += 1;
    }

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

    /// Env inheritance has no pure seam — proven through a real child.
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

    /// Signal 0 succeeds even for an unreaped zombie (a reparented
    /// grandchild); on Linux /proc state `Z` reads dead instead.
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

    /// The `npm run dev` -> vite shape: the child shell backgrounds `sleep`,
    /// prints its pid, and waits; teardown must reach BOTH processes.
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

        // A process group survives its leader while members remain, so the
        // group signal still reaches the grandchild after the leader dies.
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

/// Placeholder-path tests — reachable on every target (static/proxy workers
/// and non-run foreground take the same call, including on Windows).
#[cfg(test)]
mod command_shutdown_tests {
    use super::*;

    /// An unconditional await on the placeholder would hang every non-Run
    /// teardown; the timeout bound makes a regression fail, not hang.
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

    /// 4_000_000 is outside any real pid namespace, so any signal fails
    /// harmlessly; pins the is_finished short-circuit with a live pid.
    #[tokio::test]
    async fn finished_monitor_shutdown_completes_immediately() {
        const BOUND: std::time::Duration = std::time::Duration::from_secs(5);
        let mut monitor = tokio::spawn(async {});
        // Let the trivial task finish so is_finished is the short-circuit
        // taken (the abort path would also be fine).
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

    /// A live foreign process (cmdline matches neither needle) must be left
    /// running; on non-needle-aware platforms the gate intentionally passes.
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

        assert!(argv_contains(&blob, "tunnel"));
        assert!(!argv_contains(&blob, "run-worker"));
        assert!(!argv_contains(&blob, "FOO"));
    }

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
    //! Windows FFI: liveness, image-name identity, KILL_ON_JOB_CLOSE (runs on
    //! the windows-latest CI matrix).

    use super::*;

    #[test]
    fn process_exists_for_self() {
        assert!(process_exists(std::process::id()));
    }

    #[test]
    fn process_exists_false_for_dead_pid() {
        assert!(!process_exists(4_000_000));
    }

    #[test]
    fn pid_matches_unknown_needle_refuses() {
        assert!(!pid_matches(std::process::id(), "totally-bogus-needle"));
    }

    /// The whole-tree kill cannot be proven in-process (it would kill this
    /// test); what is pinned is setup + clean guard drop.
    #[test]
    fn create_kill_on_close_job_succeeds_and_drops() {
        let guard = create_kill_on_close_job();
        assert!(guard.is_some(), "kill-on-close job creation failed");
        drop(guard); // must not panic / double-close
    }
}
