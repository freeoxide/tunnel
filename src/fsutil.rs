//! Private file/dir creation: Unix owner-only (0600/0700 — logs can hold
//! request URIs/paths); Windows plain creates (profile-dir ACL, no chmod).

use std::path::Path;

use anyhow::Context;

/// Append-create (owner-only on Unix, plain on Windows); blocking handle.
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

/// Create `dir` (+parents), owner-only on Unix; pre-existing dirs re-sealed.
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

/// Owner-only (0600) mode on an [`std::fs::OpenOptions`] builder; no-op on
/// Windows (profile-dir ACL, no chmod equivalent).
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
