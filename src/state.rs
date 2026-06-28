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

/// Reduce a name to a single safe path segment: any char outside
/// `[A-Za-z0-9_-]` becomes `-` (so `.`, `/`, and other separators are all
/// neutralized to dashes and can never form a self/parent-dir segment).
/// Trailing/leading dashes are intentionally NOT trimmed — trimming made
/// distinct valid names collide (e.g. `"a"` and `"-a"` both collapsed to `"a"`).
/// A result that is empty, `.`, `..`, or consists only of dashes carries no
/// usable identity, so it falls back to `"service"`. This keeps traversal
/// neutralized while preserving name distinctness.
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
    match s.as_str() {
        // Empty, a self/parent marker, or all-dashes (no identity) -> fallback.
        "" | "." | ".." => "service".to_string(),
        _ if s.chars().all(|c| c == '-') => "service".to_string(),
        _ => s,
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
        // `.` and `/` both become `-`, so `../etc` can never form a parent-dir
        // reference. Leading dashes are NOT trimmed (would collide with `etc`),
        // so the result is `---etc`.
        assert_eq!(safe_component("../etc"), "---etc");
    }

    #[test]
    fn safe_component_joins_separators_with_dashes() {
        assert_eq!(safe_component("a/b/c"), "a-b-c");
    }

    #[test]
    fn safe_component_pure_traversal_falls_back_to_service() {
        // `..` maps entirely to dots, which is unsafe (parent dir) -> "service".
        assert_eq!(safe_component(".."), "service");
    }

    #[test]
    fn safe_component_empty_falls_back_to_service() {
        // All-dashes name collapses to empty -> "service" (was "" before).
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
