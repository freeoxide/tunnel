//! Cross-platform filesystem helpers for private file/directory creation.
//!
//! On Unix, log files and the state directory can contain request URIs and
//! local filesystem paths, so they are created owner-only (mode 0600 / 0700).
//! On Windows there is no chmod-equivalent in the std API; the state tree lives
//! under the user's home directory (`~/.local/state/freeoxide/tunnel`, see
//! `state::state_base`) and is protected by the home dir's ACL rather than a
//! mode bit, so the helpers fall back to a plain create there.

use std::path::Path;

use anyhow::Context;

/// Open (creating if missing) `path` in append mode with owner-only permissions
/// on Unix, or a plain append-create on Windows. Returns the blocking file
/// handle.
pub fn open_private_append(path: impl AsRef<Path>) -> std::io::Result<std::fs::File> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }
}

/// Like [`open_private_append`] but returns a tokio file handle.
pub async fn open_private_append_async(path: impl AsRef<Path>) -> std::io::Result<tokio::fs::File> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        // tokio's `OpenOptions::mode` is a native method (not the std
        // `OpenOptionsExt` trait), so no trait import is needed here.
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .await
    }
    #[cfg(not(unix))]
    {
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
    }
}

/// Create `dir` (and parents) with owner-only permissions on Unix, or a plain
/// recursive create on Windows. Pre-existing directories are left as-is.
pub fn ensure_private_dir(dir: impl AsRef<Path>) -> anyhow::Result<()> {
    let dir = dir.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating directory {}", dir.display()))?;
        // Re-seal an existing tree created by an older build to 0700.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .create(dir)
            .with_context(|| format!("creating directory {}", dir.display()))?;
    }
    Ok(())
}

/// Apply owner-only (0600) permissions to an [`std::fs::OpenOptions`] builder on
/// Unix; a no-op on Windows, where the state tree already lives under the
/// user-private profile and the std API has no chmod equivalent. Returns the
/// builder so callers can keep chaining.
pub fn apply_private_mode(opts: &mut std::fs::OpenOptions) -> &mut std::fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
    }
    // No-op: Windows file privacy comes from the profile-dir ACL, not a mode bit.
    #[cfg(not(unix))]
    {
        opts
    }
}
