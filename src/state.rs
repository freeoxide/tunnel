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

    /// Advisory lock file serializing all registry mutations.
    pub fn lock_path(&self) -> PathBuf {
        self.root.join("registry.lock")
    }

    pub fn services_dir(&self) -> PathBuf {
        self.root.join("services")
    }

    /// Per-service directory. The name is reduced to a single safe path segment
    /// so a registry-controlled (possibly hand-edited) name can never traverse
    /// out of `services/` via `..` or separators.
    pub fn service_dir(&self, name: &str) -> PathBuf {
        self.services_dir().join(safe_component(name))
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
/// A relative `XDG_STATE_HOME` is made absolute against the current directory so
/// the registry/log tree always lives at a stable absolute location.
fn state_base() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|s| !s.is_empty()) {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Ok(p);
        }
        return Ok(std::path::absolute(&p).context("resolving relative XDG_STATE_HOME")?);
    }
    let home = BaseDirs::new()
        .context("could not determine a home directory for state storage")?
        .home_dir()
        .to_path_buf();
    Ok(home.join(".local").join("state"))
}

/// Reduce a name to a single safe path segment: only `[A-Za-z0-9_-]`, with
/// surrounding dashes trimmed. Valid service names are unchanged; a hostile
/// name like `../etc` collapses to `etc`.
fn safe_component(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    s.trim_matches('-').to_string()
}
