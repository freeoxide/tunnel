//! Core data model: services, their lifecycle, and the on-disk registry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Lifecycle state of a tunnel service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    /// Worker spawned, public URL not yet discovered.
    Starting,
    /// URL discovered and the worker process is alive.
    Running,
    /// Registered but the worker process is no longer alive.
    Stale,
}

impl ServiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceStatus::Starting => "starting",
            ServiceStatus::Running => "running",
            ServiceStatus::Stale => "stale",
        }
    }
}

/// What the service exposes. The MVP only supports static directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    Static,
}

/// A single managed tunnel service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Stable numeric ID, shown in `ft ls` and usable as a target.
    pub id: u64,
    /// Human-friendly name, usable as a target.
    pub name: String,
    pub kind: ServiceKind,
    /// Absolute path to the directory being served.
    pub dir: PathBuf,
    /// Local port the static server binds on.
    pub port: u16,
    /// e.g. `http://127.0.0.1:PORT`.
    pub local_url: String,
    /// Public trycloudflare URL. `None` until the worker discovers it.
    pub public_url: Option<String>,
    /// PID of the detached worker process (it hosts the static server
    /// in-process and owns the `cloudflared` child).
    pub worker_pid: u32,
    /// PID of the `cloudflared` child, once spawned.
    pub tunnel_pid: Option<u32>,
    pub created_at: DateTime<Utc>,
    /// Per-service directory holding its log files.
    pub state_dir: PathBuf,
    /// True when the server + cloudflared run in-process inside the `ft`
    /// process the operator is watching (i.e. `ft <dir> --foreground`),
    /// rather than inside a detached `run-worker` child.
    ///
    /// Drives status/kill/prune behaviour: a foreground service's worker_pid is
    /// the `ft` process itself (whose cmdline lacks the `"run-worker"` token),
    /// so the cmdline-aware liveness probe must not be used, and `ft kill` must
    /// signal that single pid rather than its whole process group (which would
    /// include the operator's shell). Defaults to `false` so legacy registries
    /// (and background workers) keep their existing behaviour.
    #[serde(default)]
    pub foreground: bool,
}

impl Service {
    /// Compute the current status by probing the worker PID.
    ///
    /// The static server runs in-process inside the worker, so worker liveness
    /// implies server liveness.
    pub fn status(&self) -> ServiceStatus {
        // A worker_pid of 0 means the parent reserved the entry but has not yet
        // recorded the spawned worker's pid. Treat that as Starting rather than
        // probing pid 0 (which would otherwise read as Stale during the spawn
        // window).
        if self.worker_pid == 0 {
            return ServiceStatus::Starting;
        }
        // A foreground service hosts the server in-process inside THIS `ft`
        // process, whose cmdline is `ft <dir> --foreground` (no `"run-worker"`
        // token). The cmdline-aware `pid_alive` would therefore wrongly read
        // false for a live foreground tunnel, so fall back to a plain liveness
        // probe there. Background workers keep the cmdline check so PID reuse
        // can never make a recycled foreign pid read as ours.
        let alive = if self.foreground {
            crate::proc::process_exists(self.worker_pid)
        } else {
            crate::proc::pid_alive(self.worker_pid)
        };
        match (alive, self.public_url.as_ref()) {
            (false, _) => ServiceStatus::Stale,
            (true, Some(_)) => ServiceStatus::Running,
            (true, None) => ServiceStatus::Starting,
        }
    }
}

/// On-disk registry of all known services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub next_id: u64,
    #[serde(default)]
    pub services: Vec<Service>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            next_id: 1,
            services: Vec::new(),
        }
    }
}

/// Current UTC instant.
///
/// Sourced from `SystemTime` rather than chrono's `Utc::now()` (which lives
/// behind the `clock` feature). We keep `clock` disabled in `Cargo.toml` so
/// the crate never pulls `iana-time-zone` — and, on macOS, `core-foundation`
/// plus the CoreFoundation *framework*. This is the only "now" the code needs
/// (timestamps are always UTC), and it lets the binary link under a
/// cross-linker that does not ship the Apple SDK frameworks. chrono provides
/// `From<SystemTime> for DateTime<Utc>` under just the `std` feature.
pub fn now_utc() -> DateTime<Utc> {
    std::time::SystemTime::now().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn service(worker_pid: u32, public_url: Option<&str>, foreground: bool) -> Service {
        Service {
            id: 1,
            name: "alpha".to_string(),
            kind: ServiceKind::Static,
            dir: PathBuf::from("/tmp/dir"),
            port: 1234,
            local_url: "http://127.0.0.1:1234".to_string(),
            public_url: public_url.map(str::to_string),
            worker_pid,
            tunnel_pid: None,
            created_at: super::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground,
        }
    }

    #[test]
    fn status_starting_when_worker_pid_zero() {
        // A worker_pid of 0 means the parent reserved the entry but hasn't yet
        // recorded the spawned pid. This branch never touches the filesystem,
        // so it is safe to unit-test without /proc. Even with a public_url
        // present, a zero worker_pid must read as Starting.
        assert_eq!(
            service(0, Some("https://example.trycloudflare.com"), false).status(),
            ServiceStatus::Starting
        );
    }

    #[cfg(unix)] // exercises the Unix cmdline-needle behaviour of pid_alive.
    #[test]
    fn status_background_own_pid_reads_stale() {
        // A BACKGROUND service whose worker_pid is this very process: the test
        // binary's cmdline lacks the `"run-worker"` needle, so the cmdline-aware
        // pid_alive probe must read false (Stale) even though the pid is alive.
        // This locks the cmdline-needle behaviour that distinguishes bg workers.
        let me = std::process::id();
        assert_eq!(
            service(me, Some("https://example.trycloudflare.com"), false).status(),
            ServiceStatus::Stale
        );
    }

    #[cfg(unix)]
    #[test]
    fn status_foreground_running_when_alive() {
        // A FOREGROUND service whose worker_pid is this process: process_exists
        // (signal-0) reads true, and with a public_url it is Running.
        let me = std::process::id();
        assert_eq!(
            service(me, Some("https://example.trycloudflare.com"), true).status(),
            ServiceStatus::Running
        );
    }

    #[cfg(unix)]
    #[test]
    fn status_foreground_stale_when_pid_gone() {
        // A foreground service whose pid no longer exists reads Stale. 4_000_000
        // is far outside any real pid namespace on a test host.
        assert_eq!(
            service(4_000_000, None, true).status(),
            ServiceStatus::Stale
        );
    }
}
