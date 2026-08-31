//! Core data model: services, their lifecycle, and the on-disk registry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

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

/// How a tunnel service sources its local HTTP origin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    /// `ft` runs its own static file server for [`Service::dir`] and the
    /// tunnel fronts that server.
    #[default]
    Static,
    /// The operator already runs a server on [`Service::port`]; the tunnel
    /// fronts it directly and `ft` starts no server of its own.
    Proxy,
}

impl ServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceKind::Static => "static",
            ServiceKind::Proxy => "proxy",
        }
    }
}

/// A single managed tunnel service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Service {
    /// Stable numeric ID, shown in `ft ls` and usable as a target.
    pub id: u64,
    /// Human-friendly name, usable as a target.
    pub name: String,
    /// How this service sources its local origin: ft's own static server
    /// ([`ServiceKind::Static`]) or the operator's existing upstream
    /// ([`ServiceKind::Proxy`]).
    ///
    /// Defaults to `Static` on deserialize so pre-proxy `registry.json`
    /// files — which carry no `kind` — keep their existing meaning.
    #[serde(default)]
    pub kind: ServiceKind,
    /// Absolute path to the directory being served. `None` for `Proxy`
    /// services, which front an existing port instead of a directory.
    /// Nullable and defaulted so proxy entries may omit it on disk.
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// Local port. For `Static` services this is the port ft's own server
    /// binds; for `Proxy` services it IS the operator's upstream port
    /// (there is no separate local server port).
    pub port: u16,
    /// e.g. `http://127.0.0.1:PORT` — ft's server for `Static`, the
    /// operator's upstream for `Proxy`.
    pub local_url: String,
    /// Public trycloudflare URL. `None` until the worker discovers it.
    pub public_url: Option<String>,
    /// PID of the detached worker process. For `Static` services it hosts
    /// the static server in-process; for `Proxy` services it only owns the
    /// `cloudflared` child. Either way it owns that child.
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

/// How long a freshly reserved entry whose worker pid has not been recorded
/// yet (`worker_pid == 0`) is protected from `ft kill` / `ft prune` — see
/// [`Service::start_in_progress`].
///
/// The background start flow reserves the entry with `worker_pid: 0` in one
/// locked write, spawns the worker, and records the real pid in a second
/// write. During that window there is nothing safe to signal: pid 0 never
/// passes an identity probe, so reaping the entry would orphan the
/// just-spawned worker (it would keep serving a tunnel no registry entry
/// tracks). Every live start resolves the window almost immediately — the pid
/// lands within milliseconds, or the parent removes the entry on spawn
/// failure, on worker death, or on URL timeout (bounded by the 30 s poll in
/// `cmd::start`) — so this grace is set well above all of those paths: once
/// it expires, an entry whose pid is still 0 is an abandoned reservation
/// (the parent died mid-start), never a start in progress, and may be
/// cleaned up like any other stale entry.
pub const START_GRACE: Duration = Duration::from_secs(60);

impl Service {
    /// Compute the current status by probing the worker PID.
    ///
    /// This is kind-agnostic: for `Static` services the server runs
    /// in-process inside the worker (worker liveness implies server
    /// liveness), and for `Proxy` services the worker's only job is owning
    /// the `cloudflared` child.
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

    /// True while this entry sits in the reserve→spawn→record window that
    /// `ft kill` / `ft prune` must leave alone (the M1 race).
    ///
    /// Complements [`status`]'s `worker_pid == 0` special case: `status`
    /// renders such an entry as `Starting` for display, while this decides
    /// whether it may be *reaped* yet — fresh reservations are protected for
    /// [`START_GRACE`], expired ones are abandoned and fair game.
    pub fn start_in_progress(&self) -> bool {
        if self.worker_pid != 0 {
            return false;
        }
        // A negative age (clock skew between the reserving parent and now)
        // still means "freshly reserved": clamp it to zero so the entry stays
        // protected instead of instantly losing the grace.
        let age = now_utc()
            .signed_duration_since(self.created_at)
            .to_std()
            .unwrap_or(Duration::ZERO);
        age < START_GRACE
    }
}

/// On-disk registry of all known services.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
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
    use chrono::TimeDelta;
    use std::path::PathBuf;

    fn service(worker_pid: u32, public_url: Option<&str>, foreground: bool) -> Service {
        Service {
            id: 1,
            name: "alpha".to_string(),
            kind: ServiceKind::Static,
            dir: Some(PathBuf::from("/tmp/dir")),
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

    /// A minimal JSON service body covering every non-defaulted field, used
    /// to pin the serde contract (`kind` tag names, `dir` nullability).
    fn service_json(extra: &str) -> String {
        format!(
            r#"{{
            "id": 1,
            "name": "alpha",
            {extra}
            "port": 1234,
            "local_url": "http://127.0.0.1:1234",
            "public_url": null,
            "worker_pid": 0,
            "tunnel_pid": null,
            "created_at": "2026-07-21T00:00:00Z",
            "state_dir": "/tmp/state"
        }}"#
        )
    }

    #[test]
    fn legacy_entry_without_kind_deserializes_as_static() {
        // A pre-proxy registry entry carries no `kind` and a plain `dir`;
        // it must keep deserializing as a Static service, unchanged.
        let json = service_json(r#""dir": "/tmp/dir","#);
        let s: Service = serde_json::from_str(&json).expect("legacy entry must parse");
        assert_eq!(s.kind, ServiceKind::Static);
        assert_eq!(s.dir, Some(PathBuf::from("/tmp/dir")));
    }

    #[test]
    fn explicit_kind_tags_deserialize() {
        // tests/integration.rs fixtures seed `"kind": "static"` explicitly;
        // proxy entries tag `"proxy"` and may carry `"dir": null`.
        let json = service_json(r#""kind": "static", "dir": "/tmp/dir","#);
        let s: Service = serde_json::from_str(&json).expect("explicit static must parse");
        assert_eq!(s.kind, ServiceKind::Static);

        let json = service_json(r#""kind": "proxy", "dir": null,"#);
        let s: Service = serde_json::from_str(&json).expect("proxy must parse");
        assert_eq!(s.kind, ServiceKind::Proxy);
        assert_eq!(s.dir, None);
    }

    #[test]
    fn proxy_entry_may_omit_dir_entirely() {
        // `dir` is serde-defaulted, so a hand-written proxy entry without a
        // `dir` key is accepted (and reads back as None).
        let json = service_json(r#""kind": "proxy","#);
        let s: Service = serde_json::from_str(&json).expect("dir-less proxy must parse");
        assert_eq!(s.kind, ServiceKind::Proxy);
        assert_eq!(s.dir, None);
    }

    #[test]
    fn proxy_service_round_trips_through_json() {
        // A proxy service (dir: None) must survive a serialize → deserialize
        // cycle field-for-field, including the `kind` tag and null `dir`.
        let s = Service {
            kind: ServiceKind::Proxy,
            dir: None,
            ..service(7, Some("https://example.trycloudflare.com"), false)
        };
        let encoded = serde_json::to_string(&s).expect("encode");
        let decoded: Service = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn kind_as_str_matches_serde_tags() {
        // `as_str` is the human/CLI rendering and must agree with the on-disk
        // serde tag for each variant.
        assert_eq!(ServiceKind::Static.as_str(), "static");
        assert_eq!(ServiceKind::Proxy.as_str(), "proxy");
        assert_eq!(
            serde_json::to_value(ServiceKind::Proxy).expect("encode"),
            serde_json::json!("proxy")
        );
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

    // --- the reserve→spawn→record protection window (M1) ---------------------

    #[test]
    fn start_in_progress_true_for_fresh_reservation() {
        // A just-reserved entry (pid not yet recorded) is inside the protected
        // window: reaping it now would orphan the just-spawned worker.
        assert!(service(0, None, false).start_in_progress());
    }

    #[test]
    fn start_in_progress_false_once_grace_expires() {
        // An unrecorded pid past START_GRACE is an abandoned reservation (the
        // parent died mid-start) — no longer protected.
        let mut s = service(0, None, false);
        s.created_at = now_utc()
            - (TimeDelta::from_std(START_GRACE).expect("grace fits") + TimeDelta::seconds(1));
        assert!(!s.start_in_progress());
    }

    #[test]
    fn start_in_progress_false_once_pid_recorded() {
        // The window ends the moment the real pid lands, regardless of age —
        // a recorded pid gets the normal liveness semantics instead.
        assert!(!service(123_456, None, false).start_in_progress());
    }
}
