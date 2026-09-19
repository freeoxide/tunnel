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
    /// `ft run -- <command>`: `ft` spawns the operator's command (a dev
    /// server) as the origin on [`Service::port`]. Unlike `Proxy`, `ft` OWNS
    /// the child: it runs in its own process group so `ft kill` tears tunnel
    /// and command down together, and [`Service::command_pid`] records it so
    /// a survivor can still be found after the worker is gone.
    Run,
    /// `ft hook`: ft's own webhook receiver/inspector origin on
    /// [`Service::port`] (like `Static`, inside the worker), recording every
    /// request through the tunnel to the service's `requests.json` — no
    /// served directory.
    Hook,
    /// `ft drop <dir>`: ft's own upload-receiver origin on [`Service::port`]
    /// (ft-owned like Static/Hook) that accepts token-gated uploads into
    /// [`Service::dir`] (carried like Static's) and serves the stored files
    /// back GET-only.
    Drop,
}

impl ServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceKind::Static => "static",
            ServiceKind::Proxy => "proxy",
            ServiceKind::Run => "run",
            ServiceKind::Hook => "hook",
            ServiceKind::Drop => "drop",
        }
    }
}

/// Static-origin behaviour flags (`ft <dir> --spa/--cors/--token`), carried on
/// a [`Service`] so the detached worker re-applies what the operator asked for.
/// They travel on the registry entry — not the worker argv — because the
/// worker already reloads the entry before starting, and an argv channel would
/// put the `token` secret in `ps` output. Meaningless for non-Static kinds
/// (the CLI only accepts them on the implicit START; `ft proxy` structurally
/// has none).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticFlags {
    /// `--spa`: fall unmatched paths (404s for non-existent files) back to the
    /// root `index.html` for client-side-router deep links. Refusal 404s keep
    /// their meaning: dotfiles, traversal, and symlink escapes are never
    /// rewritten; a root without an `index.html` keeps the honest 404.
    pub spa: bool,
    /// `--cors`: stamp permissive CORS headers (`Access-Control-Allow-Origin:
    /// *`, methods GET/HEAD/OPTIONS, wildcard request headers) on every
    /// response. Preflight OPTIONS is deliberately NOT answered with success
    /// (it 405s like any non-GET/HEAD), so with `--token` a cross-origin
    /// BROWSER can never complete a Bearer-authenticated request (it falls
    /// back to `?token=`); same-origin pages and non-browser clients are
    /// unaffected.
    pub cors: bool,
    /// `--token <secret>`: require this operator-chosen secret on EVERY
    /// request (the static origin's whole value is its content — no safe
    /// unauthenticated subset, unlike the drop bucket's write-only gate) via
    /// `Authorization: Bearer` or `?token=`, constant-time compared, 401
    /// before confinement so a 404-scanner cannot probe the tree shape.
    /// Never auto-generated; stored here because the registry save path is
    /// owner-only 0600, like the drop token's private file.
    pub token: Option<String>,
}

/// A single managed tunnel service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Service {
    /// Stable numeric ID, shown in `ft ls` and usable as a target.
    pub id: u64,
    /// Human-friendly name, usable as a target.
    pub name: String,
    /// How this service sources its local origin: ft's own static file server
    /// ([`Static`]), the operator's existing upstream ([`Proxy`]), a command
    /// `ft` spawns itself ([`Run`]), ft's own webhook receiver ([`Hook`]), or
    /// ft's own upload receiver ([`Drop`]). Defaults to `Static` on
    /// deserialize so pre-proxy registries (no `kind` key) keep their meaning.
    #[serde(default)]
    pub kind: ServiceKind,
    /// Absolute path to the directory being served: `Some` for `Static` (the
    /// served tree) and `Drop` (the upload target); `None` for `Proxy`/`Run`/
    /// `Hook`, which front a port instead. Nullable and defaulted so those
    /// entries may omit it on disk.
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
    /// Static-origin flags for `Static` services (`--spa`/`--cors`/`--token`),
    /// persisted so the detached worker re-applies them — see [`StaticFlags`]
    /// for why they live here rather than on the worker argv. Serde-defaulted
    /// so pre-flag registries and non-Static entries load with all flags off.
    #[serde(default)]
    pub static_flags: StaticFlags,
    /// PID of the user's command child, for `Run` services only: recorded
    /// under the registry lock so the child stays reachable by id even if the
    /// worker dies without tearing it down (`ft doctor`'s orphan detection
    /// reads this field). Only the pid is registry state — the command line
    /// travels in the worker's argv and is deliberately not persisted.
    #[serde(default)]
    pub command_pid: Option<u32>,
    pub created_at: DateTime<Utc>,
    /// Per-service directory holding its log files.
    pub state_dir: PathBuf,
    /// True when the server + cloudflared run in-process inside the `ft`
    /// process the operator is watching (`--foreground`) rather than a
    /// detached `run-worker` child. Drives status/kill behaviour: the
    /// worker_pid is the `ft` process itself (cmdline lacks the
    /// `"run-worker"` token, so the cmdline-aware probe must not be used),
    /// and `ft kill` signals that single pid, never the whole group (which
    /// would include the operator's shell). Defaults to `false`.
    #[serde(default)]
    pub foreground: bool,
}

/// How long a freshly reserved entry whose worker pid has not been recorded
/// (`worker_pid == 0`) is protected from `ft kill` / `ft prune` — see
/// [`Service::start_in_progress`]. The background flow reserves with pid 0,
/// spawns the worker, then records the pid; during that window there is
/// nothing safe to signal (pid 0 never passes an identity probe, and reaping
/// the entry would orphan the just-spawned worker). Every live start resolves
/// the window in milliseconds or removes the entry on failure (bounded by the
/// 30 s poll), so 60 s is well above all of those: past the grace, a pid-0
/// entry is an abandoned reservation (parent died mid-start), fair game.
pub const START_GRACE: Duration = Duration::from_secs(60);

impl Service {
    /// Compute the current status by probing the worker PID (kind-agnostic:
    /// the server, when there is one, runs inside the worker).
    pub fn status(&self) -> ServiceStatus {
        // worker_pid 0 = reserved but not yet recorded: Starting, never a
        // pid-0 probe (which would read Stale during the spawn window).
        if self.worker_pid == 0 {
            return ServiceStatus::Starting;
        }
        // A foreground service's worker_pid is the `ft` process itself (no
        // `"run-worker"` cmdline token), so the cmdline-aware `pid_alive`
        // would wrongly read false for a live tunnel — use a plain liveness
        // probe there. Background workers keep the cmdline check so a
        // recycled foreign pid can never read as ours.
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
    /// `ft kill` / `ft prune` must leave alone (the M1 race). Complements
    /// [`status`]'s pid-0 case: that renders `Starting` for display, this
    /// decides reapability — fresh reservations are protected for
    /// [`START_GRACE`], expired ones are abandoned and fair game.
    pub fn start_in_progress(&self) -> bool {
        if self.worker_pid != 0 {
            return false;
        }
        // A negative age (clock skew) still counts as freshly reserved: clamp
        // to zero so the entry keeps its grace.
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

/// Current UTC instant, from `SystemTime` rather than chrono's `Utc::now()`:
/// `clock` stays disabled so the crate never pulls `iana-time-zone` (and, on
/// macOS, the CoreFoundation framework), which lets the binary link under a
/// cross-linker without the Apple SDK. `From<SystemTime> for DateTime<Utc>`
/// exists under just the `std` feature.
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
            static_flags: StaticFlags::default(),
            command_pid: None,
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
        // Every on-disk kind tag round-trips; proxy/run/hook carry `dir: null`.
        let json = service_json(r#""kind": "static", "dir": "/tmp/dir","#);
        let s: Service = serde_json::from_str(&json).expect("explicit static must parse");
        assert_eq!(s.kind, ServiceKind::Static);

        let json = service_json(r#""kind": "proxy", "dir": null,"#);
        let s: Service = serde_json::from_str(&json).expect("proxy must parse");
        assert_eq!(s.kind, ServiceKind::Proxy);
        assert_eq!(s.dir, None);

        let json = service_json(r#""kind": "run", "dir": null,"#);
        let s: Service = serde_json::from_str(&json).expect("run must parse");
        assert_eq!(s.kind, ServiceKind::Run);
        assert_eq!(s.dir, None);

        let json = service_json(r#""kind": "hook", "dir": null,"#);
        let s: Service = serde_json::from_str(&json).expect("hook must parse");
        assert_eq!(s.kind, ServiceKind::Hook);
        assert_eq!(s.dir, None);

        let json = service_json(r#""kind": "drop", "dir": "/tmp/inbox","#);
        let s: Service = serde_json::from_str(&json).expect("drop must parse");
        assert_eq!(s.kind, ServiceKind::Drop);
        assert_eq!(s.dir, Some(PathBuf::from("/tmp/inbox")));
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
    fn run_service_round_trips_through_json() {
        // dir: None plus the command child's recorded pid must round-trip.
        let s = Service {
            kind: ServiceKind::Run,
            dir: None,
            command_pid: Some(4242),
            ..service(7, Some("https://example.trycloudflare.com"), false)
        };
        let encoded = serde_json::to_string(&s).expect("encode");
        let decoded: Service = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn hook_service_round_trips_through_json() {
        // A hook service (dir: None, no command child) must round-trip.
        let s = Service {
            kind: ServiceKind::Hook,
            dir: None,
            ..service(7, Some("https://example.trycloudflare.com"), false)
        };
        let encoded = serde_json::to_string(&s).expect("encode");
        let decoded: Service = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn drop_service_round_trips_through_json() {
        // dir: Some (the upload target). The token is NOT registry state — it
        // lives in the service's private token file.
        let s = Service {
            kind: ServiceKind::Drop,
            dir: Some(PathBuf::from("/tmp/inbox")),
            ..service(7, Some("https://example.trycloudflare.com"), false)
        };
        let encoded = serde_json::to_string(&s).expect("encode");
        let decoded: Service = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn omitted_command_pid_deserializes_as_none() {
        // serde-defaulted: pre-run registries and non-run entries read as
        // "no command child", never fail the parse.
        let json = service_json(r#""kind": "proxy", "dir": null,"#);
        let s: Service = serde_json::from_str(&json).expect("entry without command_pid");
        assert_eq!(s.command_pid, None);
    }

    #[test]
    fn omitted_static_flags_deserialize_as_all_off() {
        // serde-defaulted: pre-flag registries read as all flags off, never
        // fail the parse.
        let json = service_json(r#""kind": "static", "dir": "/tmp/dir","#);
        let s: Service = serde_json::from_str(&json).expect("entry without static_flags");
        assert_eq!(s.static_flags, StaticFlags::default());
        assert!(!s.static_flags.spa);
        assert!(!s.static_flags.cors);
        assert_eq!(s.static_flags.token, None);
    }

    #[test]
    fn static_flags_round_trip_through_json() {
        // The flags ARE the persistence story: the detached worker re-applies
        // exactly these values (token included) from the reloaded entry.
        let s = Service {
            static_flags: StaticFlags {
                spa: true,
                cors: true,
                token: Some("hunter2".to_string()),
            },
            ..service(7, Some("https://example.trycloudflare.com"), false)
        };
        let encoded = serde_json::to_string(&s).expect("encode");
        let decoded: Service = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn explicit_static_flags_json_deserializes() {
        // The on-disk shape a flagged start reserves; partial objects work too
        // (container-level serde default).
        let json = service_json(
            r#""kind": "static", "dir": "/tmp/dir",
            "static_flags": {"spa": true, "cors": false, "token": "s"},"#,
        );
        let s: Service = serde_json::from_str(&json).expect("flagged entry must parse");
        assert!(s.static_flags.spa);
        assert!(!s.static_flags.cors);
        assert_eq!(s.static_flags.token.as_deref(), Some("s"));

        let json =
            service_json(r#""kind": "static", "dir": "/tmp/dir", "static_flags": {"spa": true},"#);
        let s: Service = serde_json::from_str(&json).expect("partial flag group must parse");
        assert!(s.static_flags.spa);
        assert!(!s.static_flags.cors);
        assert_eq!(s.static_flags.token, None);
    }

    #[test]
    fn kind_as_str_matches_serde_tags() {
        // `as_str` is the human/CLI rendering and must agree with the on-disk
        // serde tag for each variant.
        assert_eq!(ServiceKind::Static.as_str(), "static");
        assert_eq!(ServiceKind::Proxy.as_str(), "proxy");
        assert_eq!(ServiceKind::Run.as_str(), "run");
        assert_eq!(ServiceKind::Hook.as_str(), "hook");
        assert_eq!(ServiceKind::Drop.as_str(), "drop");
        assert_eq!(
            serde_json::to_value(ServiceKind::Proxy).expect("encode"),
            serde_json::json!("proxy")
        );
        assert_eq!(
            serde_json::to_value(ServiceKind::Run).expect("encode"),
            serde_json::json!("run")
        );
        assert_eq!(
            serde_json::to_value(ServiceKind::Hook).expect("encode"),
            serde_json::json!("hook")
        );
        assert_eq!(
            serde_json::to_value(ServiceKind::Drop).expect("encode"),
            serde_json::json!("drop")
        );
    }

    #[test]
    fn status_starting_when_worker_pid_zero() {
        // Even with a public_url present, a zero worker_pid reads as Starting
        // (no filesystem probe involved).
        assert_eq!(
            service(0, Some("https://example.trycloudflare.com"), false).status(),
            ServiceStatus::Starting
        );
    }

    #[cfg(unix)] // exercises the Unix cmdline-needle behaviour of pid_alive.
    #[test]
    fn status_background_own_pid_reads_stale() {
        // The test binary's cmdline lacks the `"run-worker"` needle, so the
        // cmdline-aware probe must read false (Stale) even though we are alive.
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
