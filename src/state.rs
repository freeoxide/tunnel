//! Locations of the on-disk state directory and derived paths.
//!
//! Uses the [`directories`] crate so the location follows OS conventions.
//! On Linux this resolves to `~/.local/state/freeoxide/tunnel/`.

use crate::error::Result;
use anyhow::Context;
use directories::ProjectDirs;
use std::path::{Path, PathBuf};

/// Rooted handle to the on-disk state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Locate the OS-appropriate state directory for Freeoxide Tunnel.
    pub fn new() -> Result<Self> {
        let dirs = ProjectDirs::from("", "freeoxide", "tunnel")
            .context("could not determine a state directory for this platform")?;
        let state_dir = dirs
            .state_dir()
            .context("could not determine a state directory for this platform")?;
        Ok(Self {
            root: state_dir.to_path_buf(),
        })
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
