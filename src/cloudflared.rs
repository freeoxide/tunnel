//! Discovery and lifecycle of the `cloudflared` Quick Tunnel process.
//!
//! `cloudflared` is an external binary downloaded by the user; we never
//! vendor it. This module locates it on `PATH`, parses the Quick Tunnel URL
//! from its log output, and spawns it as a tokio child whose `stdout` and
//! `stderr` are piped back to the caller.

use crate::error::Result;
use anyhow::{Context, bail};
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;
use tokio::process::{Child, Command};

/// Grace window after SIGTERM before SIGKILL'ing cloudflared (Unix only; the
/// Windows teardown force-kills the owned child).
#[cfg(unix)]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// The exact message shown when `cloudflared` cannot be found on `PATH`.
const MISSING_MESSAGE: &str = "\
cloudflared was not found.

Freeoxide Tunnel uses cloudflared for Cloudflare Quick Tunnels.
Install cloudflared, then try again:

    Linux:   https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
    macOS:   brew install cloudflared
    Windows: winget install Cloudflare.cloudflared";

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

/// True if `url` is an `https://` URL whose host ends with `.trycloudflare.com`.
///
/// Used to re-validate a stored `public_url` before it is handed to the browser
/// launcher: `public_url` lives in the user-editable `registry.json`, so we
/// cannot assume it still has the shape [`extract_url`] produced.
pub fn is_tunnel_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', '?']).next().unwrap_or("");
    !host.is_empty() && host.ends_with(".trycloudflare.com")
}

/// Spawn a `cloudflared` Quick Tunnel pointing at the local server.
///
/// The child's `stdout` and `stderr` are piped; the caller is responsible
/// for reading them line by line, applying [`extract_url`], and teeing the
/// output to `tunnel.log`.
pub fn spawn(port: u16) -> Result<Child> {
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

    // cloudflared deliberately inherits the spawner's process group: the
    // worker's group kill reaches it directly (even if the worker already died
    // and cannot relay a signal), and a terminal Ctrl+C reaches it in the
    // foreground flow. NO setsid() here — that would orphan it on kill.

    // On Linux, PDEATHSIG asks the kernel to SIGKILL cloudflared if the worker
    // dies — even via SIGKILL/OOM — so no orphaned tunnel remains. The hook
    // (shared with the command-child spawn) re-checks getppid() after prctl to
    // close the fork→prctl reparenting window, and surfaces a failed prctl
    // instead of exec'ing without the death signal. See
    // [`crate::proc::parent_death_signal`].
    #[cfg(target_os = "linux")]
    unsafe {
        cmd.pre_exec(crate::proc::parent_death_signal);
    }

    let child = cmd
        .spawn()
        .context("failed to spawn cloudflared tunnel process")?;
    Ok(child)
}

/// Shut down a `cloudflared` child this process owns, then reap it (shared by
/// the detached worker and the foreground flow). Unix: SIGTERM by pid, then
/// SIGKILL after [`SHUTDOWN_GRACE`]. Windows: no signal/group teardown — the
/// owned child is force-killed (the worker's Job Object reaps it on the
/// worker's exit). No-op after `child.wait()` has already reaped it.
pub async fn shutdown(tunnel_pid: Option<u32>, child: &mut Child) {
    #[cfg(unix)]
    {
        if let Some(pid) = tunnel_pid {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        if tokio::time::timeout(SHUTDOWN_GRACE, child.wait())
            .await
            .is_err()
            && let Some(pid) = tunnel_pid
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
    #[cfg(not(unix))]
    {
        // No signal path on Windows; the owned handle is the kill vector.
        let _ = tunnel_pid;
        let _ = child.start_kill();
    }

    let _ = child.wait().await; // ensure reaped
}

#[cfg(test)]
mod tests {
    use super::{extract_url, is_tunnel_url};

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
        // Scans left-to-right, returns the first trycloudflare host.
        let line = "your tunnel: https://my-tunnel.trycloudflare.com  docs: https://developers.cloudflare.com/";
        assert_eq!(
            extract_url(line),
            Some("https://my-tunnel.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn skips_non_tunnel_url_before_tunnel_url() {
        // A non-tunnel https:// before the tunnel URL is skipped.
        let line = "docs: https://developers.cloudflare.com/  tunnel: https://real-tunnel.trycloudflare.com";
        assert_eq!(
            extract_url(line),
            Some("https://real-tunnel.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn keeps_path_and_query_in_returned_url() {
        // `ft open` hands the URL verbatim to the browser: path + query stay.
        let line = "your tunnel: https://x.trycloudflare.com/foo?bar=1";
        assert_eq!(
            extract_url(line),
            Some("https://x.trycloudflare.com/foo?bar=1".to_string())
        );
    }

    #[test]
    fn uppercase_https_is_rejected() {
        // cloudflared always emits lowercase; prose must not match.
        assert_eq!(extract_url("HTTPS://x.trycloudflare.com"), None);
    }

    #[test]
    fn empty_input_returns_none() {
        // Guards the `?` early-return on a whitespace split of empty input.
        assert_eq!(extract_url(""), None);
    }

    #[test]
    fn picks_tunnel_when_non_tunnel_url_comes_after() {
        // The trailing non-tunnel candidate must not distract the scan.
        let line = "tunnel: https://real-tunnel.trycloudflare.com  docs: https://developers.cloudflare.com/";
        assert_eq!(
            extract_url(line),
            Some("https://real-tunnel.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn is_tunnel_url_accepts_valid() {
        assert!(is_tunnel_url("https://foo-bar.trycloudflare.com"));
        assert!(is_tunnel_url(
            "https://foo-bar.trycloudflare.com/some/path?x=1"
        ));
    }

    #[test]
    fn is_tunnel_url_rejects_non_https_and_spoofs() {
        assert!(!is_tunnel_url("http://foo.trycloudflare.com"));
        assert!(!is_tunnel_url("ftp://foo.trycloudflare.com"));
        // No leading dot: not a subdomain of trycloudflare.com.
        assert!(!is_tunnel_url("https://eviltrycloudflare.com"));
        // Suffix trick: host taken before any '/'.
        assert!(!is_tunnel_url("https://foo.trycloudflare.com.evil.example"));
        assert!(!is_tunnel_url("not a url"));
    }

    // --- property test ----------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// Anything extract_url returns is always a well-formed Quick Tunnel URL:
        /// `https://` + a host ending in `.trycloudflare.com`, and it round-trips
        /// through `is_tunnel_url`.
        #[test]
        fn extract_url_only_yields_tunnel_urls(
            prefix in "[a-zA-Z0-9 .,|:!?/<>\"'-]{0,40}",
            slug in "[a-z0-9-]{1,30}",
            suffix in "[^\\x00]{0,20}"
        ) {
            let line = format!("{prefix}https://{slug}.trycloudflare.com{suffix}");
            if let Some(url) = extract_url(&line) {
                let rest = url.strip_prefix("https://").unwrap_or("");
                let host = rest.split(['/', '?']).next().unwrap_or("");
                prop_assert!(!host.is_empty() && host.ends_with(".trycloudflare.com"), "bad url: {url}");
                // The returned URL must re-validate through is_tunnel_url, so a
                // stored public_url always round-trips through both checks.
                prop_assert!(is_tunnel_url(&url), "returned url failed is_tunnel_url: {url}");
            }
        }

        /// With a non-tunnel `https://host` placed AFTER the tunnel URL, the
        /// tunnel URL is still the one returned (exercises the scan-past loop
        /// from the right side).
        #[test]
        fn picks_tunnel_when_non_tunnel_follows(
            prefix in "[a-zA-Z0-9 .,|:!?/<>\"'-]{0,20}",
            slug in "[a-z0-9-]{1,30}",
        ) {
            let line = format!(
                "{prefix}https://{slug}.trycloudflare.com see https://developers.cloudflare.com/"
            );
            let expected = format!("https://{slug}.trycloudflare.com");
            let got = extract_url(&line);
            prop_assert_eq!(got.as_deref(), Some(expected.as_str()));
        }
    }
}
