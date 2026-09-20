//! State dir + derived paths (`$XDG_STATE_HOME/freeoxide/tunnel`). The suffix
//! is hand-built: `directories` v6 ignores `organization` on Linux.

use crate::error::Result;
use anyhow::Context;
use directories::BaseDirs;
use std::path::{Path, PathBuf};

/// Rooted handle to the on-disk state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    /// Locate the state directory for Freeoxide Tunnel.
    pub fn new() -> Result<Self> {
        let root = state_base()?.join("freeoxide").join("tunnel");
        Ok(Self { root })
    }

    /// Root directly at `root` — used by tests to point at a tempdir without
    /// mutating XDG_STATE_HOME (unsafe in edition 2024).
    #[cfg(test)]
    pub(crate) fn new_at(root: PathBuf) -> Self {
        Self { root }
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

    /// Per-service directory; the name is sanitized to one safe path segment
    /// so a hand-edited registry name cannot traverse out of `services/`.
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

    /// Create the tree, owner-only (0700) — registry/logs must not be
    /// others-readable; pre-existing dirs are re-sealed.
    pub fn ensure(&self) -> Result<()> {
        // Plain recursive create on Windows: the profile-dir ACL suffices.
        crate::fsutil::ensure_private_dir(self.services_dir())
            .with_context(|| format!("creating state directory {}", self.root.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Re-seal the root itself, which `services_dir()`'s create may not
            // have touched.
            let _ = std::fs::set_permissions(self.root(), std::fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    /// Create (or reuse) a single service's private directory with mode 0700
    /// and return it. Holds that service's `worker.log`/`server.log`/`tunnel.log`.
    pub fn ensure_service_dir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.service_dir(name);
        // Owner-only (0700) on Unix; plain create on Windows.
        crate::fsutil::ensure_private_dir(&dir)
            .with_context(|| format!("creating service directory for '{name}'"))?;
        Ok(dir)
    }
}

/// The XDG state base (`$XDG_STATE_HOME`, else `~/.local/state`); a relative
/// value is made absolute so the tree lives at a stable location.
fn state_base() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|s| !s.is_empty()) {
        let p = PathBuf::from(xdg);
        if !p.is_absolute() {
            return std::path::absolute(&p).context("resolving relative XDG_STATE_HOME");
        }
        return Ok(p);
    }
    let home = BaseDirs::new()
        .context("could not determine a home directory for state storage")?
        .home_dir()
        .to_path_buf();
    Ok(home.join(".local").join("state"))
}

/// One safe path segment via [`dash_sanitize`]: outside `[A-Za-z0-9_-]`
/// becomes `-` (no traversal possible); all-dashes -> `"service"`.
fn safe_component(name: &str) -> String {
    let s = crate::name::dash_sanitize(name);
    // All-dashes (which also covers the empty string — `all` is vacuously
    // true there) means no usable identity -> fallback.
    if s.chars().all(|c| c == '-') {
        "service".to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_component_passes_simple_name() {
        assert_eq!(safe_component("blog"), "blog");
    }

    #[test]
    fn safe_component_neutralizes_traversal() {
        // `.` and `/` both become `-`; leading dashes are not trimmed.
        assert_eq!(safe_component("../etc"), "---etc");
    }

    #[test]
    fn safe_component_joins_separators_with_dashes() {
        assert_eq!(safe_component("a/b/c"), "a-b-c");
    }

    #[test]
    fn safe_component_pure_traversal_falls_back_to_service() {
        assert_eq!(safe_component(".."), "service");
    }

    #[test]
    fn safe_component_empty_falls_back_to_service() {
        assert_eq!(safe_component("---"), "service");
    }

    #[test]
    fn safe_component_does_not_trim_dashes() {
        // Trimming would collide "-a" with "a"; both must stay distinct.
        assert_eq!(safe_component("-a"), "-a");
        assert_eq!(safe_component("a-"), "a-");
        assert_eq!(safe_component("a"), "a");
    }

    #[test]
    fn safe_component_keeps_underscores_and_dashes() {
        assert_eq!(safe_component("blog_1-2"), "blog_1-2");
    }
}
