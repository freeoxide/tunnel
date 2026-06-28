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
        .read(true)
        .write(true)
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
        let data = std::fs::read(&path)
            .with_context(|| format!("reading registry {}", path.display()))?;
        if data.iter().all(u8::is_ascii_whitespace) {
            return Ok(Registry::default());
        }
        serde_json::from_slice::<Registry>(&data)
            .with_context(|| format!("registry file {} is corrupted", path.display()))
    }

    /// Atomically persist the registry (write temp file, then rename).
    pub fn save(&self, state: &StateDir) -> Result<()> {
        let path = state.registry_path();
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(self).context("encoding registry")?;
        std::fs::write(&tmp, &data)
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
