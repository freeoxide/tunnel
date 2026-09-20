//! Local port allocation helpers.

use crate::error::Result;
use anyhow::Context;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Loopback connect-probe bound: the local kernel answers almost instantly,
/// so this only bounds pathological stacks; nothing is read from the socket.
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Bind `127.0.0.1:0` for an OS-picked port. Inherent TOCTOU: if it is taken
/// before the real bind, that bind fails loudly and the start surfaces it.
pub fn allocate_free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("finding a free port")?;
    let port = listener
        .local_addr()
        .context("reading the allocated local port")?
        .port();
    Ok(port)
}

/// True if the port appears free on localhost: connect; "refused" = free,
/// anything else (accepted, timeout, unreachable) = occupied.
///
/// Connect-based on purpose: a just-stopped server's port sits in TIME_WAIT
/// where a plain bind fails EADDRINUSE though nothing serves — nothing
/// ACCEPTS either, so the probe reads it free and a dev server (which sets
/// SO_REUSEADDR itself) can rebind. SO_REUSEADDR as the probe was rejected:
/// on Windows it permits binding over a LIVE listener (hijack hazard). Port
/// 0 stays free so the worker's dedicated "reserved" bail is what fires.
pub fn is_port_free(port: u16) -> bool {
    if port == 0 {
        return true;
    }
    let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), port);
    match std::net::TcpStream::connect_timeout(&addr, PROBE_TIMEOUT) {
        Ok(_) => false,
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_returns_ephemeral_port_that_is_free() {
        let p = allocate_free_port().expect("allocate");
        assert!(p > 0, "OS-assigned port must be non-zero");
        assert!(
            is_port_free(p),
            "a freshly allocated port should read as free"
        );
    }

    #[test]
    fn is_port_free_is_false_while_a_port_is_held() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        assert!(
            !is_port_free(port),
            "port should read as in-use while the listener is held"
        );
        drop(listener);
    }

    #[test]
    fn a_port_left_in_time_wait_by_a_just_stopped_server_reads_free() {
        // Server closes first (active close), then the client — the port sits
        // in TIME_WAIT with no listener; a restart must be allowed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let accepted = listener.accept().expect("accept").0;
        // Drop order is the point: the server's active close while the client
        // is still open drives the server endpoint into TIME_WAIT.
        drop(listener);
        drop(accepted);
        drop(client);

        assert!(is_port_free(port), "a TIME_WAIT-only port must read free");
    }

    #[test]
    fn port_zero_stays_reported_free() {
        // Must reach the worker's dedicated "port 0 is reserved" bail.
        assert!(is_port_free(0), "port 0 must keep reading as free");
    }
}
