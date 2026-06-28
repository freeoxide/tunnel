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
        let alive = crate::proc::pid_alive(self.worker_pid);
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;

    #[test]
    fn status_starting_when_worker_pid_zero() {
        // A worker_pid of 0 means the parent reserved the entry but hasn't yet
        // recorded the spawned pid. This branch never touches the filesystem,
        // so it is safe to unit-test without /proc.
        let svc = Service {
            id: 1,
            name: "alpha".to_string(),
            kind: ServiceKind::Static,
            dir: PathBuf::from("/tmp/dir"),
            port: 1234,
            local_url: "http://127.0.0.1:1234".to_string(),
            public_url: Some("https://example.trycloudflare.com".to_string()),
            worker_pid: 0,
            tunnel_pid: None,
            created_at: Utc::now(),
            state_dir: PathBuf::from("/tmp/state"),
        };
        // Even with a public_url present, a zero worker_pid must read as Starting.
        assert_eq!(svc.status(), ServiceStatus::Starting);
    }
}
