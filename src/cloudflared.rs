//! Discovery and lifecycle of the `cloudflared` Quick Tunnel process.
//!
//! `cloudflared` is an external binary downloaded by the user; we never
//! vendor it. This module locates it on `PATH`, parses the Quick Tunnel URL
//! from its log output, and spawns it as a tokio child whose `stdout` and
//! `stderr` are piped back to the caller.

use crate::error::Result;
use anyhow::{Context, bail};
use std::path::PathBuf;
use tokio::process::{Child, Command};

/// The exact message shown when `cloudflared` cannot be found on `PATH`.
const MISSING_MESSAGE: &str = "\
cloudflared was not found.

Freeoxide Tunnel requires cloudflared for Cloudflare Quick Tunnels.
Install cloudflared and try again:
https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/";

/// Ensure `cloudflared` is installed and on `PATH`.
///
/// Returns the resolved path to the binary on success. On failure, bails
/// out with the friendly install message rather than a raw lookup error.
pub fn ensure_installed() -> Result<PathBuf> {
    match which::which("cloudflared") {
        Ok(path) => Ok(path),
        Err(_) => bail!(MISSING_MESSAGE),
    }
}

/// Extract the first Quick Tunnel URL from a line of `cloudflared` output.
///
/// Looks for `https://` and takes the run of non-whitespace characters that
/// follow. The result is accepted only if the host component ends with
/// `.trycloudflare.com`; anything else (e.g. a documentation link) is
/// ignored and `None` is returned.
pub fn extract_url(text: &str) -> Option<String> {
    let start = text.find("https://")?;
    let rest = &text[start..];
    // The URL runs until the next whitespace character.
    let url = rest.split_whitespace().next()?;
    // Strip any trailing punctuation that cloudflared occasionally appends.
    let url = url.trim_end_matches(['.', ')', ',', ';', '"', '\'']);
    let host = url
        .strip_prefix("https://")
        .and_then(|s| s.split('/').next())
        .unwrap_or("");
    if host.ends_with(".trycloudflare.com") {
        Some(url.to_string())
    } else {
        None
    }
}

/// Spawn a `cloudflared` Quick Tunnel pointing at the local server.
///
/// The child's `stdout` and `stderr` are piped; the caller is responsible
/// for reading them line by line, applying [`extract_url`], and teeing the
/// output to `tunnel.log`. `tunnel_log` is accepted for API symmetry but is
/// not opened here so this function stays focused on spawning.
pub fn spawn(port: u16, _tunnel_log: PathBuf) -> Result<Child> {
    let cloudflared = ensure_installed()?;

    let mut cmd = Command::new(cloudflared);
    cmd.args([
        "tunnel",
        "--no-autoupdate",
        "--url",
        &format!("http://127.0.0.1:{port}"),
    ])
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());

    // cloudflared deliberately inherits the spawner's process group: in the
    // worker flow it joins the worker's group so `kill(-worker_pid)` reaches it
    // directly (even if the worker has already died and can no longer relay a
    // signal), and in the foreground flow a terminal Ctrl+C reaches it along
    // with `ft`. We do NOT `setsid()` here — that would orphan it on kill.

    let child = cmd
        .spawn()
        .context("failed to spawn cloudflared tunnel process")?;
    Ok(child)
}
