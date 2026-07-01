//! Persistence and querying of the service registry.
//!
//! All mutations go through [`Registry::update`], which holds an exclusive
//! `flock` on `registry.lock` for the whole load → modify → save sequence. This
//! serializes concurrent `ft` invocations so they cannot clobber each other's
//! writes, allocate duplicate IDs, or erase fields another writer just published.

use crate::error::Result;
use crate::fsutil;
use crate::model::{Registry, Service};
use crate::state::StateDir;
use anyhow::Context;
use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::Write;

/// An advisory lock on the registry, released on drop.
///
/// `fs2` grants a cross-platform exclusive lock — `flock(LOCK_EX)` on Unix and
/// `LockFileEx` on Windows — bound to this file handle. Both OSes release the
/// lock automatically when the handle is closed, so dropping this guard (which
/// drops and closes the file) frees it without an explicit unlock call. Calling
/// `fs2::FileExt::unlock` directly trips a `clippy::incompatible_msrv` false
/// positive that misattributes the trait method to the std library, so we rely
/// on close-on-drop instead.
struct RegistryLock(#[allow(dead_code)] std::fs::File);

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

impl Registry {
    /// Load the registry, returning an empty one if it does not yet exist.
    ///
    /// Cleans up any `registry.json.tmp` left by a crash between the temp write
    /// and the rename, validates the parsed content (healing `next_id` and
    /// rejecting clearly-broken entries), and falls back to `registry.json.bak`
    /// if the live file is missing or unparseable — so a botched commit can no
    /// longer brick the whole CLI.
    pub fn load(state: &StateDir) -> Result<Registry> {
        let path = state.registry_path();
        // NOTE: orphan `registry.json.tmp` cleanup is performed under the lock
        // in `acquire_lock`, not here — `load` is also called by unlocked
        // read-only commands, which must not race a concurrent writer's temp.

        if let Some(bytes) = std::fs::read(&path).ok()
            && !bytes.iter().all(u8::is_ascii_whitespace)
        {
            return match Registry::parse(&bytes) {
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
        let bytes = std::fs::read(&bak).ok()?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        Registry::parse(&bytes).ok()
    }

    /// Atomically and durably persist the registry:
    ///
    /// 1. write a mode-0600 temp file and `fsync` it;
    /// 2. best-effort copy the previous registry to `registry.json.bak`;
    /// 3. atomically rename temp → `registry.json`;
    /// 4. `fsync` the parent directory so the rename survives power loss.
    pub fn save(&self, state: &StateDir) -> Result<()> {
        let path = state.registry_path();
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(self).context("encoding registry")?;
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
        // Recovery snapshot of the previous registry (copy, not rename, so the
        // live file stays in place right up to the atomic replace below).
        let _ = std::fs::copy(&path, path.with_extension("json.bak"));
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("committing registry {}", path.display()))?;
        // Make the rename durable too.
        sync_parent_dir(&path);
        Ok(())
    }

    /// Sanity-check a loaded registry, healing `next_id` so future allocations
    /// stay monotonic. Rejects clearly-broken state (reserved id 0, duplicate
    /// ids/names, empty names, reserved port 0) that would otherwise cause
    /// confusing behavior downstream.
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
            if s.port == 0 {
                anyhow::bail!("service {:?} binds reserved port 0", s.name);
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
            dir: PathBuf::from("/tmp/dir"),
            port: 1234,
            local_url: "http://127.0.0.1:1234".to_string(),
            public_url: None,
            worker_pid: 0,
            tunnel_pid: None,
            created_at: crate::model::now_utc(),
            state_dir: PathBuf::from("/tmp/state"),
            foreground: false,
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
        // An all-digit target must resolve as an ID, never as a same-named service.
        let mut reg = Registry::default();
        reg.services.push(dummy_service(1, "111"));
        reg.services.push(dummy_service(42, "real"));
        // Target "1" parses as ID 1; it must not match the service *named* "111".
        let found = reg.find("1").expect("id 1 should resolve");
        assert_eq!(found.id, 1);
        assert_eq!(found.name, "111");
        // Conversely, "42" is the ID of "real", not a name lookup.
        let found = reg.find("42").expect("id 42 should resolve");
        assert_eq!(found.id, 42);
        assert_eq!(found.name, "real");
        // "111" parses as ID 111, which doesn't exist (it is NOT a name lookup).
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
        // SR-2: an unlocked read (Registry::load) must NOT delete a writer's
        // in-flight registry.json.tmp, or a concurrent reader could fail the
        // writer's commit. Only acquire_lock (under the exclusive flock) cleans it.
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
}
