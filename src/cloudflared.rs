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
/// Scans every `https://` occurrence left-to-right. For each candidate the
/// host is taken by stripping the `https://` prefix and reading up to the
/// first `/` or `?`. The first candidate whose host ends with
/// `.trycloudflare.com` is returned (with trailing punctuation stripped);
/// any earlier non-tunnel `https://` (e.g. a documentation link) is skipped.
pub fn extract_url(text: &str) -> Option<String> {
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find("https://") {
        let start = search_from + rel;
        let rest = &text[start..];
        // The URL runs until the next whitespace character.
        let url = rest.split_whitespace().next()?;
        // Strip any trailing punctuation that cloudflared occasionally appends.
        let url = url.trim_end_matches(['.', ')', ',', ';', '"', '\'']);
        // Host = after `https://`, up to the first `/` or `?`.
        let host = url
            .strip_prefix("https://")
            .map(|s| s.split(['/', '?']).next().unwrap_or(""))
            .unwrap_or("");
        if host.ends_with(".trycloudflare.com") {
            return Some(url.to_string());
        }
        // Advance past this `https://` and keep scanning for a later tunnel URL.
        search_from = start + "https://".len();
    }
    None
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

    // Best-effort: on Linux, ask the kernel to SIGKILL cloudflared if its
    // parent (the worker) dies — even via SIGKILL or OOM — so we never leave
    // an orphaned tunnel behind when the worker is killed abnormally while
    // cloudflared is idle. prctl result is ignored (best-effort).
    #[cfg(target_os = "linux")]
    unsafe {
        cmd.pre_exec(|| {
            let _ = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
            Ok(())
        });
    }

    let child = cmd
        .spawn()
        .context("failed to spawn cloudflared tunnel process")?;
    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::extract_url;

    #[test]
    fn real_cloudflared_table_line() {
        let line = "...  |  https://random-words.trycloudflare.com  |";
        assert_eq!(
            extract_url(line),
            Some("https://random-words.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn trailing_punctuation_stripped() {
        let line = "url: https://x-y.trycloudflare.com.";
        assert_eq!(
            extract_url(line),
            Some("https://x-y.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn plain_url() {
        let line = "https://x.trycloudflare.com";
        assert_eq!(
            extract_url(line),
            Some("https://x.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn non_tunnel_https_url_ignored() {
        let line = "https://developers.cloudflare.com/cloudflare-one/connections/";
        assert_eq!(extract_url(line), None);
    }

    #[test]
    fn no_url_returns_none() {
        let line = "cloudflared is starting up, please wait";
        assert_eq!(extract_url(line), None);
    }

    #[test]
    fn picks_trycloudflare_among_two_urls() {
        // The first https:// is the tunnel URL; a later non-tunnel URL is
        // present but never examined. extract_url scans left-to-right and
        // returns as soon as it finds the trycloudflare host.
        let line = "your tunnel: https://my-tunnel.trycloudflare.com  docs: https://developers.cloudflare.com/";
        assert_eq!(
            extract_url(line),
            Some("https://my-tunnel.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn skips_non_tunnel_url_before_tunnel_url() {
        // A non-tunnel https:// precedes the trycloudflare URL on the same
        // line. extract_url must skip it and return the later tunnel URL.
        let line = "docs: https://developers.cloudflare.com/  tunnel: https://real-tunnel.trycloudflare.com";
        assert_eq!(
            extract_url(line),
            Some("https://real-tunnel.trycloudflare.com".to_string())
        );
    }
}
