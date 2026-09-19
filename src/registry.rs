//! Persistence and querying of the service registry.
//!
//! All mutations go through [`Registry::update`], which holds an exclusive
//! `flock` on `registry.lock` for the whole load → modify → save sequence. This
//! serializes concurrent `ft` invocations so they cannot clobber each other's
//! writes, allocate duplicate IDs, or erase fields another writer just published.

use crate::error::Result;
use crate::fsutil;
use crate::model::{Registry, Service, ServiceKind};
use crate::state::StateDir;
use anyhow::Context;
use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::Write;

/// An advisory lock on the registry, released on drop. `fs2` grants a
/// cross-platform exclusive lock (flock/LOCK_EX, LockFileEx) bound to this
/// file handle; both OSes release it when the handle closes, so drop frees it
/// without an explicit unlock (calling `fs2::FileExt::unlock` trips a
/// `clippy::incompatible_msrv` false positive).
struct RegistryLock(#[allow(dead_code)] std::fs::File);

/// Hard upper bound on a persisted registry blob we are willing to read: the
/// registry is a small operator-owned JSON document, so anything past this
/// bound is corruption (e.g. a log redirected over `registry.json`), and
/// bounding the READ itself stops a multi-GB stray file being slurped whole
/// before the parser rejects it.
const MAX_REGISTRY_BYTES: u64 = 16 * 1024 * 1024;

/// Read a persisted registry blob with the hard size bound above: at most
/// `MAX_REGISTRY_BYTES + 1` bytes are ever read (the +1 lets callers tell
/// "at the bound" from "past it" by length alone). Returns `None` when the
/// file is missing or unreadable, mirroring plain `std::fs::read(path).ok()`.
fn read_registry_blob(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_REGISTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

fn acquire_lock(state: &StateDir) -> Result<RegistryLock> {
    let path = state.lock_path();
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).write(true);
    fsutil::apply_private_mode(&mut opts);
    let file = opts
        .open(&path)
        .with_context(|| format!("opening registry lock {}", path.display()))?;
    // Block until we hold an exclusive advisory lock on the lock file.
    file.lock_exclusive()
        .with_context(|| format!("locking registry {}", path.display()))?;
    // Now that we hold the exclusive lock, drop any leftover temp file from a
    // save that crashed before its rename. Doing this HERE (under the lock)
    // rather than on every unlocked `load` means a concurrent read-only command
    // can never delete a writer's in-flight temp mid-save and fail its commit.
    let _ = std::fs::remove_file(state.registry_path().with_extension("json.tmp"));
    Ok(RegistryLock(file))
}

/// Best-effort `fsync` of the directory holding `path`, so a rename/creat
/// performed there survives a power loss. Errors (e.g. on filesystems that
/// cannot sync a directory) are ignored — durability here is best-effort.
fn sync_parent_dir(path: &std::path::Path) {
    let Some(dir) = path.parent() else { return };
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

/// Best-effort re-seal of an existing file to owner-only (0600) on Unix, mirroring
/// the directory re-seal in `StateDir::ensure`. No-op on Windows (file privacy
/// comes from the profile-dir ACL). Used by `load`/`load_backup` so a registry
/// created by an older build or hand-edited under a loose umask is healed on read.
fn seal_private_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

impl Registry {
    /// Load the registry, returning an empty one if it does not yet exist.
    ///
    /// Cleans up any orphan `registry.json.tmp` (under the lock, in
    /// `acquire_lock`), validates the parsed content, and falls back to
    /// `registry.json.bak` if the live file is missing or unparseable — so a
    /// botched commit cannot brick the whole CLI.
    pub fn load(state: &StateDir) -> Result<Registry> {
        let path = state.registry_path();
        // NOTE: orphan-tmp cleanup lives in `acquire_lock`, not here — `load`
        // is also called by unlocked read-only commands, which must not race a
        // concurrent writer's temp.

        if let Some(bytes) = read_registry_blob(&path)
            && !bytes.iter().all(u8::is_ascii_whitespace)
        {
            // Oversized = corruption: route it through the same recovery as a
            // parse failure (backup, else a loud error), never the missing-file
            // path — a stray huge file must not yield a silent fresh default.
            let parsed = if bytes.len() > MAX_REGISTRY_BYTES as usize {
                Err(anyhow::anyhow!(
                    "blob is larger than the {MAX_REGISTRY_BYTES}-byte safety bound"
                ))
            } else {
                Registry::parse(&bytes)
            };
            // Best-effort re-seal to 0600: heal a pre-0600 build's or a loose
            // umask's registry on read (mirrors StateDir::ensure's dir re-seal).
            seal_private_file(&path);
            return match parsed {
                Ok(reg) => Ok(reg),
                Err(e) => match Self::load_backup(state) {
                    Some(reg) => Ok(reg),
                    None => Err(e)
                        .with_context(|| format!("registry file {} is corrupted", path.display())),
                },
            };
        }

        // Missing or empty live file: prefer the backup, else a fresh default.
        Ok(Self::load_backup(state).unwrap_or_default())
    }

    /// Decode + validate a registry blob.
    fn parse(bytes: &[u8]) -> Result<Registry> {
        let mut reg: Registry = serde_json::from_slice(bytes).context("decoding registry")?;
        reg.validate().context("validating registry")?;
        Ok(reg)
    }

    /// Best-effort load of `registry.json.bak`, used when the live file is
    /// missing or corrupt. Returns `None` if there is no usable backup.
    fn load_backup(state: &StateDir) -> Option<Registry> {
        let bak = state.registry_path().with_extension("json.bak");
        let bytes = read_registry_blob(&bak)?;
        if bytes.len() > MAX_REGISTRY_BYTES as usize || bytes.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        let parsed = Registry::parse(&bytes).ok()?;
        // Heal perms on the backup too, so the same recovery point never stays
        // world-readable after a one-time loose-umask write.
        seal_private_file(&bak);
        Some(parsed)
    }

    /// Atomically and durably persist the registry: write a 0600 temp + fsync,
    /// promote the previous blob to `.bak` (only if it parses+validates, so the
    /// backup stays a known-good recovery point), rename temp → live, fsync the
    /// parent dir.
    pub fn save(&self, state: &StateDir) -> Result<()> {
        let path = state.registry_path();
        let tmp = path.with_extension("json.tmp");
        // Compact encoding: registry.json is read via `ft detail`/`ft ls`, not
        // by eye, so pretty-print's 2-3x overhead is waste.
        let data = serde_json::to_vec(self).context("encoding registry")?;
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            fsutil::apply_private_mode(&mut opts);
            let mut file = opts
                .open(&tmp)
                .with_context(|| format!("writing registry temp file {}", tmp.display()))?;
            file.write_all(&data)
                .with_context(|| format!("writing registry temp file {}", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("fsyncing registry temp file {}", tmp.display()))?;
        }
        // Copy (not rename) the previous blob to `.bak` only if it
        // parses+validates, so tampered content never overwrites a good backup.
        if let Some(prev) = read_registry_blob(&path)
            && prev.len() <= MAX_REGISTRY_BYTES as usize
            && !prev.iter().all(u8::is_ascii_whitespace)
            && Registry::parse(&prev).is_ok()
        {
            // Owner-only like every other registry write: the .bak can carry
            // static_flags token secrets (defense-in-depth atop the 0700 root).
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            fsutil::apply_private_mode(&mut opts);
            // Best-effort, like the fs::write it replaces.
            if let Ok(mut file) = opts.open(path.with_extension("json.bak")) {
                let _ = file.write_all(&prev);
            }
            // mode(0o600) applies only at creation — re-seal a legacy .bak
            // that a pre-fix build left at umask-default 0644.
            seal_private_file(&path.with_extension("json.bak"));
        }
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("committing registry {}", path.display()))?;
        // Make the rename durable too.
        sync_parent_dir(&path);
        Ok(())
    }

    /// Sanity-check a loaded registry: heal `next_id` past the highest id, and
    /// reject clearly-broken state (reserved id 0, duplicate ids/names, empty
    /// names, reserved port 0). Kind/dir consistency is strict — a `dir` on a
    /// proxy entry (or its absence on a static one) is a hand-edited shape no
    /// code path produces, so reject rather than guess.
    pub fn validate(&mut self) -> Result<()> {
        let mut ids = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for s in &self.services {
            if s.id == 0 {
                anyhow::bail!("service {:?} has reserved id 0", s.name);
            }
            if !ids.insert(s.id) {
                anyhow::bail!("duplicate service id {}", s.id);
            }
            if s.name.is_empty() {
                anyhow::bail!("service id {} has an empty name", s.id);
            }
            if !names.insert(s.name.as_str()) {
                anyhow::bail!("duplicate service name {:?}", s.name);
            }
            // 0 is unusable for both kinds: Static binds it, Proxy fronts the
            // operator's server on it.
            if s.port == 0 {
                anyhow::bail!("service {:?} has reserved port 0", s.name);
            }
            match (s.kind, s.dir.as_ref()) {
                (ServiceKind::Static, None) => {
                    anyhow::bail!("{} service {:?} has no directory", s.kind.as_str(), s.name);
                }
                (ServiceKind::Proxy, Some(_)) => {
                    anyhow::bail!(
                        "{} service {:?} must not carry a directory",
                        s.kind.as_str(),
                        s.name
                    );
                }
                _ => {}
            }
        }
        // Keep the id counter strictly ahead of every existing id so a hand-
        // edited entry can never collide with a future allocation.
        let max_id = self.services.iter().map(|s| s.id).max().unwrap_or(0);
        if self.next_id <= max_id {
            self.next_id = max_id.saturating_add(1);
        }
        Ok(())
    }

    /// Run `f` against a fresh registry snapshot under an exclusive lock, then
    /// persist. Use for every mutation so concurrent writers are serialized.
    pub fn update<R, F>(state: &StateDir, f: F) -> Result<R>
    where
        F: FnOnce(&mut Registry) -> R,
    {
        let _lock = acquire_lock(state)?;
        let mut reg = Registry::load(state)?;
        let result = f(&mut reg);
        reg.save(state)?;
        Ok(result)
    }

    /// Allocate the next service ID and advance the counter (saturating).
    pub fn allocate_id(&mut self) -> u64 {
        let id = self.next_id.max(1);
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Find a service by numeric ID (if `target` is all digits) or by name.
    ///
    /// Per the design, an all-digit target always resolves as an ID — never as
    /// a (possibly numeric) name.
    pub fn find(&self, target: &str) -> Option<&Service> {
        match target.parse::<u64>() {
            Ok(id) => self.services.iter().find(|s| s.id == id),
            Err(_) => self.services.iter().find(|s| s.name == target),
        }
    }

    /// Mutable counterpart of [`Registry::find`].
    pub fn find_mut(&mut self, target: &str) -> Option<&mut Service> {
        match target.parse::<u64>() {
            Ok(id) => self.services.iter_mut().find(|s| s.id == id),
            Err(_) => self.services.iter_mut().find(|s| s.name == target),
        }
    }

    /// Remove and return the service with the given ID, if present.
    pub fn remove(&mut self, id: u64) -> Option<Service> {
        self.services
            .iter()
            .position(|s| s.id == id)
            .map(|i| self.services.remove(i))
    }

    /// True if a service with this name is already registered.
    pub fn name_exists(&self, name: &str) -> bool {
        self.services.iter().any(|s| s.name == name)
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{Registry, Service, ServiceKind};
    use std::path::PathBuf;

    fn dummy_service(id: u64, name: &str) -> Service {
        Service {
            id,
            name: name.to_string(),
            kind: ServiceKind::Static,
            dir: Some(PathBuf::from("/tmp/dir")),
            port: 1234,
            local_url: "http://127.0.0.1:1234".to_string(),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            command_pid: None,
            static_flags: Default::default(),
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
        }
    }

    /// A `Proxy` counterpart of `dummy_service`: fronts an upstream port,
    /// no directory.
    fn dummy_proxy_service(id: u64, name: &str) -> Service {
        Service {
            kind: ServiceKind::Proxy,
            dir: None,
            ..dummy_service(id, name)
        }
    }

    #[test]
    fn find_by_numeric_id() {
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "alpha"));
        reg.services.push(dummy_service(2, "beta"));
        let found = reg.find("2").expect("id 2 should resolve");
        assert_eq!(found.id, 2);
        assert_eq!(found.name, "beta");
    }

    #[test]
    fn find_by_name() {
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "alpha"));
        reg.services.push(dummy_service(2, "beta"));
        let found = reg.find("alpha").expect("name alpha should resolve");
        assert_eq!(found.id, 1);
        assert_eq!(found.name, "alpha");
    }

    #[test]
    fn find_all_digit_target_matches_id_not_name() {
        // An all-digit target always resolves as an ID, never as a name.
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "111"));
        reg.services.push(dummy_service(42, "real"));
        let found = reg.find("1").expect("id 1 should resolve");
        assert_eq!(found.id, 1);
        assert_eq!(found.name, "111");
        let found = reg.find("42").expect("id 42 should resolve");
        assert_eq!(found.id, 42);
        assert_eq!(found.name, "real");
        assert!(reg.find("111").is_none());
    }

    #[test]
    fn find_mut_updates_service() {
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "alpha"));
        {
            let s = reg.find_mut("1").expect("id 1 should resolve mutably");
            s.port = 9999;
        }
        assert_eq!(reg.services[0].port, 9999);
        // And by name.
        {
            let s = reg.find_mut("alpha").expect("name should resolve mutably");
            s.worker_pid = 7;
        }
        assert_eq!(reg.services[0].worker_pid, 7);
    }

    #[test]
    fn allocate_id_sequence_from_default() {
        let mut reg = Registry::default();
        assert_eq!(reg.allocate_id(), 1);
        assert_eq!(reg.allocate_id(), 2);
        assert_eq!(reg.allocate_id(), 3);
        assert_eq!(reg.next_id, 4);
    }

    #[test]
    fn allocate_id_respects_non_default_next_id() {
        let mut reg = Registry {
            next_id: 100,
            services: Vec::new(),
        };
        assert_eq!(reg.allocate_id(), 100);
        assert_eq!(reg.allocate_id(), 101);
        assert_eq!(reg.next_id, 102);
    }

    #[test]
    fn remove_returns_and_drops_service() {
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "alpha"));
        reg.services.push(dummy_service(2, "beta"));
        let removed = reg.remove(1).expect("id 1 should be removed");
        assert_eq!(removed.id, 1);
        assert_eq!(removed.name, "alpha");
        assert_eq!(reg.services.len(), 1);
        assert_eq!(reg.services[0].id, 2);
        // Removing again is None; removing an absent id is None.
        assert!(reg.remove(1).is_none());
        assert!(reg.remove(99).is_none());
    }

    #[test]
    fn name_exists() {
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "alpha"));
        assert!(reg.name_exists("alpha"));
        assert!(!reg.name_exists("beta"));
        assert!(!reg.name_exists("1"));
    }

    // --- concurrency: the exclusive flock must serialize writers -------------

    #[test]
    fn flock_serializes_concurrent_writers() {
        use crate::state::StateDir;
        use std::sync::Arc;
        use std::thread;

        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new_at(tmp.path().join("ft-state"));
        state.ensure().expect("ensure state dir");
        // Seed an empty registry so load() has a file to flock.
        Registry::default().save(&state).expect("seed save");

        let n_threads = 8;
        let per_thread = 5;
        let state = Arc::new(state);
        let mut handles = Vec::new();
        for _ in 0..n_threads {
            let state = state.clone();
            handles.push(thread::spawn(move || {
                let mut ids = Vec::new();
                for _ in 0..per_thread {
                    let id = Registry::update(&state, |reg| {
                        let id = reg.allocate_id();
                        reg.services.push(dummy_service(id, &format!("svc-{id}")));
                        id
                    })
                    .expect("update under lock");
                    ids.push(id);
                }
                ids
            }));
        }
        let mut all = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }

        // No duplicate ids were ever handed out.
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "duplicate ids allocated: {all:?}");
        assert_eq!(all.len(), n_threads * per_thread);

        // And every allocation survived to disk (no lost updates).
        let reg = Registry::load(&state).expect("final load");
        assert_eq!(reg.services.len(), n_threads * per_thread);
        assert_eq!(reg.next_id, (n_threads * per_thread + 1) as u64);
    }

    #[test]
    fn load_does_not_remove_orphan_tmp() {
        // An unlocked read must not delete a writer's in-flight tmp; only
        // acquire_lock (under the flock) cleans it.
        use crate::state::StateDir;
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new_at(tmp.path().join("ft-state"));
        state.ensure().expect("ensure");
        Registry::default().save(&state).expect("seed");
        // Simulate a writer's in-flight temp.
        let tmp_path = state.registry_path().with_extension("json.tmp");
        std::fs::write(&tmp_path, b"partial").expect("write tmp");
        // A read-only load must leave the temp alone.
        let _ = Registry::load(&state).expect("load");
        assert!(
            tmp_path.exists(),
            "unlocked load must not delete an in-flight tmp"
        );
    }

    #[test]
    fn validate_rejects_duplicate_ids_and_heals_next_id() {
        let mut reg = Registry {
            next_id: 1,
            services: vec![dummy_service(5, "a"), dummy_service(5, "dup")],
        };
        assert!(reg.validate().is_err(), "duplicate id must be rejected");

        let mut reg = Registry {
            next_id: 1, // behind the highest id below
            services: vec![dummy_service(7, "a")],
        };
        assert!(reg.validate().is_ok());
        assert_eq!(
            reg.next_id, 8,
            "next_id healed past the highest existing id"
        );
    }

    // --- kind/dir consistency of validate ------------------------------------

    #[test]
    fn validate_rejects_static_without_dir() {
        let mut s = dummy_service(1, "a");
        s.dir = None;
        let mut reg = Registry {
            next_id: 2,
            services: vec![s],
        };
        assert!(
            reg.validate().is_err(),
            "static without dir must be rejected"
        );
    }

    #[test]
    fn validate_rejects_proxy_with_dir() {
        let mut s = dummy_proxy_service(1, "a");
        s.dir = Some(PathBuf::from("/tmp/dir"));
        let mut reg = Registry {
            next_id: 2,
            services: vec![s],
        };
        assert!(reg.validate().is_err(), "proxy with dir must be rejected");
    }

    #[test]
    fn validate_accepts_proxy_without_dir() {
        let mut reg = Registry {
            next_id: 2,
            services: vec![dummy_proxy_service(1, "a")],
        };
        assert!(reg.validate().is_ok(), "proxy without dir is consistent");
    }

    #[test]
    fn validate_rejects_proxy_on_reserved_port() {
        // For a proxy, `port` IS the operator's upstream port; 0 is unusable.
        let mut s = dummy_proxy_service(1, "a");
        s.port = 0;
        let mut reg = Registry {
            next_id: 2,
            services: vec![s],
        };
        assert!(reg.validate().is_err(), "proxy on port 0 must be rejected");
    }

    #[test]
    fn parse_accepts_legacy_registry_without_kind() {
        // A pre-proxy registry.json (no `kind` keys anywhere) must load: each
        // entry defaults to Static with the directory it already carried.
        let json = r#"{
                "next_id": 2,
                "services": [
                    {
                        "id": 1,
                        "name": "legacy",
                        "dir": "/tmp/legacy",
                        "port": 8080,
                        "local_url": "http://127.0.0.1:8080",
                        "public_url": null,
                        "worker_pid": 0,
                        "tunnel_pid": null,
                        "created_at": "2026-07-21T00:00:00Z",
                        "state_dir": "/tmp/legacy-state",
                        "foreground": false
                    }
                ]
            }"#;
        let reg = Registry::parse(json.as_bytes()).expect("legacy registry must parse");
        assert_eq!(reg.services.len(), 1);
        assert_eq!(reg.services[0].kind, ServiceKind::Static);
        assert_eq!(reg.services[0].dir, Some(PathBuf::from("/tmp/legacy")));
    }

    #[test]
    fn parse_rejects_proxy_entry_with_dir() {
        // validate runs inside parse, so nonsense is rejected at load time.
        let json = r#"{
                "next_id": 2,
                "services": [
                    {
                        "id": 1,
                        "name": "broken",
                        "kind": "proxy",
                        "dir": "/tmp/leftover",
                        "port": 3000,
                        "local_url": "http://127.0.0.1:3000",
                        "public_url": null,
                        "worker_pid": 0,
                        "tunnel_pid": null,
                        "created_at": "2026-07-21T00:00:00Z",
                        "state_dir": "/tmp/state",
                        "foreground": false
                    }
                ]
            }"#;
        assert!(Registry::parse(json.as_bytes()).is_err());
    }

    // --- save→load data-integrity round-trip + corrupt recovery --------------

    /// Build a fully-populated Service with every field set to a non-default
    /// value, so a round-trip can prove each one survives serde + the atomic
    /// temp-write + .bak-copy + rename in `save`.
    fn fully_populated_service() -> Service {
        Service {
            id: 42,
            name: "blog".to_string(),
            kind: ServiceKind::Static,
            dir: Some(PathBuf::from("/srv/blog")),
            port: 8080,
            local_url: "http://127.0.0.1:8080".to_string(),
            public_url: Some("https://blog.trycloudflare.com".to_string()),
            worker_pid: 4242,
            tunnel_pid: Some(5353),
            command_pid: None,
            static_flags: Default::default(),
            // Pinned instant (SystemTime epoch) so created_at is deterministic.
            created_at: std::time::SystemTime::UNIX_EPOCH.into(),
            state_dir: PathBuf::from("/srv/ft-state/services/blog"),
            foreground: true,
        }
    }

    #[test]
    fn save_load_preserves_all_fields() {
        // Every serialization-relevant field through save()'s full path (temp
        // fsync + .bak promotion + rename + parent-dir fsync).
        use crate::state::StateDir;
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new_at(tmp.path().join("ft-state"));
        state.ensure().expect("ensure");

        let original = Registry {
            next_id: 43,
            services: vec![fully_populated_service()],
        };
        original.save(&state).expect("save");

        let reloaded = Registry::load(&state).expect("load");
        assert_eq!(
            reloaded, original,
            "registry must round-trip field-for-field"
        );
    }

    #[test]
    fn save_load_preserves_proxy_service() {
        // A proxy entry (kind: "proxy", dir: null) must survive the same
        // atomic save path — proving the null dir and the kind tag both
        // persist and re-validate on load.
        use crate::state::StateDir;
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new_at(tmp.path().join("ft-state"));
        state.ensure().expect("ensure");

        let original = Registry {
            next_id: 43,
            services: vec![Service {
                id: 42,
                name: "dev".to_string(),
                kind: ServiceKind::Proxy,
                dir: None,
                port: 3000,
                local_url: "http://127.0.0.1:3000".to_string(),
                public_url: Some("https://dev.trycloudflare.com".to_string()),
                worker_pid: 4242,
                tunnel_pid: Some(5353),
                command_pid: None,
                static_flags: Default::default(),
                created_at: std::time::SystemTime::UNIX_EPOCH.into(),
                state_dir: PathBuf::from("/srv/ft-state/services/dev"),
                foreground: false,
            }],
        };
        original.save(&state).expect("save");

        let reloaded = Registry::load(&state).expect("load");
        assert_eq!(
            reloaded, original,
            "proxy registry must round-trip field-for-field"
        );
    }

    #[test]
    fn save_promotes_the_previous_blob_to_an_owner_only_bak() {
        // Regression: the .bak used to be written with umask-default mode
        // (typically 0644); it can carry static_flags token secrets.
        #[cfg(unix)]
        {
            use crate::state::StateDir;
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().expect("tempdir");
            let state = StateDir::new_at(tmp.path().join("ft-state"));
            state.ensure().expect("ensure");

            let first = Registry {
                next_id: 43,
                services: vec![fully_populated_service()],
            };
            first.save(&state).expect("first save");
            let second = Registry {
                next_id: 44,
                services: Vec::new(),
            };
            second
                .save(&state)
                .expect("second save promotes the first blob");

            let bak = state.registry_path().with_extension("json.bak");
            let mode = std::fs::metadata(&bak)
                .expect("a valid previous blob must have been promoted")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the .bak must be owner-only");

            // Legacy trees: a pre-existing 0644 .bak (the creation-time mode
            // never applies to it) must be healed by the next promotion.
            std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o644))
                .expect("widen the .bak to a legacy mode");
            Registry::default()
                .save(&state)
                .expect("third save re-promotes the second blob");
            let mode = std::fs::metadata(&bak)
                .expect("the .bak must still exist")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "a legacy 0644 .bak must be re-sealed");
        }
    }

    #[test]
    fn load_falls_back_to_backup_when_live_corrupt() {
        // A corrupted live registry.json falls back to a valid .bak instead of
        // erroring the whole CLI.
        use crate::state::StateDir;
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new_at(tmp.path().join("ft-state"));
        state.ensure().expect("ensure");

        // Seed a known-good registry, then snapshot it as the backup. next_id
        // must be consistent with the service id, or validate() would heal it
        // on load and this would test healing, not fallback.
        let good = Registry {
            next_id: 43,
            services: vec![fully_populated_service()],
        };
        good.save(&state).expect("seed save");
        let live = state.registry_path();
        let bak = live.with_extension("json.bak");
        std::fs::copy(&live, &bak).expect("seed backup");

        // Corrupt the live file in place.
        std::fs::write(&live, b"{ this is not json").expect("corrupt live");

        let loaded = Registry::load(&state).expect("must recover from backup");
        assert_eq!(loaded, good, "load must serve the backup's contents");
    }

    #[test]
    fn load_returns_err_when_both_live_and_backup_corrupt() {
        // Neither file parses: error, never a silent fresh default.
        use crate::state::StateDir;
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new_at(tmp.path().join("ft-state"));
        state.ensure().expect("ensure");

        let live = state.registry_path();
        let bak = live.with_extension("json.bak");
        // Both present but unparseable — not empty/whitespace, so load() treats
        // them as "present and corrupt" rather than "missing".
        std::fs::write(&live, b"@@garbage@@").expect("corrupt live");
        std::fs::write(&bak, b"@@garbage@@").expect("corrupt backup");

        let res = Registry::load(&state);
        assert!(
            res.is_err(),
            "both-corrupt must error, not silently default"
        );
    }

    #[test]
    fn load_treats_oversized_registry_as_corruption() {
        // A stray huge file over registry.json is corruption: corrupt-file
        // recovery (loud error here, backup fallback if one exists), never a
        // silent fresh default over real state.
        use crate::state::StateDir;
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new_at(tmp.path().join("ft-state"));
        state.ensure().expect("ensure");
        std::fs::write(
            state.registry_path(),
            vec![b'x'; super::MAX_REGISTRY_BYTES as usize + 1],
        )
        .expect("oversized live");
        let res = Registry::load(&state);
        assert!(
            res.is_err(),
            "oversized live file with no backup must error, not default"
        );
    }
}
