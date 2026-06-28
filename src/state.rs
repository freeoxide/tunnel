//! Locations of the on-disk state directory and derived paths.
//!
//! Resolves to `$XDG_STATE_HOME/freeoxide/tunnel`, defaulting to
//! `~/.local/state/freeoxide/tunnel`. We build the `freeoxide/tunnel` suffix
//! ourselves because `directories` v6 ignores `organization` on Linux (only the
//! `application` segment is used), so `ProjectDirs` cannot produce this path.

use crate::error::Result;
use anyhow::Context;
use directories::BaseDirs;
use std::path::{Path, PathBuf};

/// Rooted handle to the on-disk state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

#[allow(dead_code)] // public surface of the state API; callers may use any of these
impl StateDir {
    /// Locate the state directory for Freeoxide Tunnel.
    pub fn new() -> Result<Self> {
        let root = state_base()?.join("freeoxide").join("tunnel");
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn registry_path(&self) -> PathBuf {
        self.root.join("registry.json")
    }

    pub fn services_dir(&self) -> PathBuf {
        self.root.join("services")
    }

    pub fn service_dir(&self, name: &str) -> PathBuf {
        self.services_dir().join(name)
    }

    pub fn worker_log(&self, name: &str) -> PathBuf {
        self.service_dir(name).join("worker.log")
    }

    pub fn server_log(&self, name: &str) -> PathBuf {
        self.service_dir(name).join("server.log")
    }

    pub fn tunnel_log(&self, name: &str) -> PathBuf {
        self.service_dir(name).join("tunnel.log")
    }

    /// Create the root and services directory tree if missing.
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(self.services_dir())
            .with_context(|| format!("creating state directory {}", self.root.display()))?;
        Ok(())
    }
}

/// Resolve the XDG state base directory (`$XDG_STATE_HOME`, else `~/.local/state`).
fn state_base() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(xdg));
    }
    let home = BaseDirs::new()
        .context("could not determine a home directory for state storage")?
        .home_dir()
        .to_path_buf();
    Ok(home.join(".local").join("state"))
}
