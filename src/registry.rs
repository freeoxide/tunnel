//! Persistence and querying of the service registry.
//!
//! All mutations go through [`Registry::update`], which holds an exclusive
//! `flock` on `registry.lock` for the whole load → modify → save sequence. This
//! serializes concurrent `ft` invocations so they cannot clobber each other's
//! writes, allocate duplicate IDs, or erase fields another writer just published.

use crate::error::Result;
use crate::model::{Registry, Service};
use crate::state::StateDir;
use anyhow::Context;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

/// An advisory lock on the registry, released on drop.
struct RegistryLock(std::fs::File);

impl Drop for RegistryLock {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn acquire_lock(state: &StateDir) -> Result<RegistryLock> {
    let path = state.lock_path();
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("opening registry lock {}", path.display()))?;
    // Block until we hold an exclusive advisory lock on the lock file.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(anyhow::anyhow!(
            "locking registry: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(RegistryLock(file))
}

impl Registry {
    /// Load the registry, returning an empty one if it does not yet exist.
    pub fn load(state: &StateDir) -> Result<Registry> {
        let path = state.registry_path();
        if !path.exists() {
            return Ok(Registry::default());
        }
        let data =
            std::fs::read(&path).with_context(|| format!("reading registry {}", path.display()))?;
        if data.iter().all(u8::is_ascii_whitespace) {
            return Ok(Registry::default());
        }
        serde_json::from_slice::<Registry>(&data)
            .with_context(|| format!("registry file {} is corrupted", path.display()))
    }

    /// Atomically persist the registry (write a mode-0600 temp file, then rename).
    ///
    /// The temp file is created with mode 0600 and the rename preserves it, so
    /// `registry.json` is owner-only even on a shared host (it records every
    /// service's absolute served-directory path).
    pub fn save(&self, state: &StateDir) -> Result<()> {
        let path = state.registry_path();
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(self).context("encoding registry")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing registry temp file {}", tmp.display()))?;
        file.write_all(&data)
            .with_context(|| format!("writing registry temp file {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("committing registry {}", path.display()))?;
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
    use chrono::Utc;
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
            created_at: Utc::now(),
            state_dir: PathBuf::from("/tmp/state"),
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
}
